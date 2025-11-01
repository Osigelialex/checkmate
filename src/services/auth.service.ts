import { StatusCodes } from "http-status-codes";
import { prisma } from "../config/db.config";
import { LoginDTO, RefreshTokenDTO, RequestPasswordResetDTO,
  ResetPasswordDTO, SignupDTO, ValidatePasswordResetDTO, VerifyOtpDTO } from "../dtos/auth.dto";
import { HttpException } from "../utils/exception.util";
import { redisClient } from "../config/redis.config";
import otpGenerator from "otp-generator";
import { MailService } from "./mail.service";
import { generateJwtToken, verifyToken } from "../utils/helpers.utils";
import { hashPassword, compareHashedPassword } from "../utils/helpers.utils";
import { OTP_TYPES } from "../utils/constants.util";
import { JwtPayload } from "jsonwebtoken";
import crypto from "crypto";

export class AuthService {
  private readonly mailService: MailService = new MailService();

  private generateAndStoreOTP = async (
    email: string,
    otpType: string,
    userId: string,
    expirySeconds: number = 600
  ): Promise<string> => {
    const code = otpGenerator.generate(6, { upperCaseAlphabets: false, specialChars: false });
    await redisClient.setex(`otp:${otpType}:${email}`, expirySeconds, JSON.stringify({
      code,
      userId
    }));

    return code;
  }

  private generateAndStoreResetToken = async (
    email: string,
    expirySeconds: number = 600
  ): Promise<string> => {
    const token = crypto.randomUUID();
    const key = `resetToken:${token}`;
    await redisClient.setex(key, expirySeconds, email);
    return token;
  }

  private verifyOTPCode = async (
    code: string,
    email: string,
    otpType: string,
  ): Promise<string> => {
    const key = `otp:${otpType}:${email}`;
    const storedOtp = await redisClient.get(key);
    if (!storedOtp) {
      throw new HttpException(StatusCodes.BAD_REQUEST, "Invalid OTP");
    }

    const { code: storedCode, userId } = JSON.parse(storedOtp);
    if (storedCode !== code) {
      throw new HttpException(StatusCodes.BAD_REQUEST, "Invalid OTP");
    }

    await redisClient.del(key);
    return userId;
  }

  public signUp = async (dto: SignupDTO) => {
    const { email, password } = dto;
    const emailExists = await prisma.user.findUnique({
      where: { email }
    });

    if (emailExists) {
      throw new HttpException(StatusCodes.BAD_REQUEST, "Email is already in use");
    }

    const passwordHash = await hashPassword(password);
    if (!passwordHash) {
      throw new HttpException(StatusCodes.INTERNAL_SERVER_ERROR,
        "Something went wrong during signup, please try again");
    }

    dto.password = passwordHash;

    const user = await prisma.user.create({ data: dto });
    const code = await this.generateAndStoreOTP(email, OTP_TYPES.EMAIL_VERIFICATION, user.id);

    await this.mailService.sendEmailOTP(email, code, OTP_TYPES.EMAIL_VERIFICATION);
  }

  public verifyOTP = async (dto: VerifyOtpDTO) => {
    const { email, code } = dto;
    const emailExists = await prisma.user.findUnique({
      where: { email }
    });

    if (!emailExists) {
      throw new HttpException(StatusCodes.BAD_REQUEST, "User not found");
    }

    const userId = await this.verifyOTPCode(code, email, OTP_TYPES.EMAIL_VERIFICATION);

    await prisma.user.update({
      where: { id: userId },
      data: {
        emailVerified: true
      }
    });

    const accessToken = await generateJwtToken(userId, "access");
    const refreshToken = await generateJwtToken(userId, "refresh");

    return { accessToken, refreshToken }
  }

  public login = async (dto: LoginDTO) => {
    const { email, password } = dto;
    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      throw new HttpException(StatusCodes.BAD_REQUEST, "Invalid email or password");
    }

    const passwordValid = await compareHashedPassword(password, user.password);
    if (!passwordValid) {
      throw new HttpException(StatusCodes.BAD_REQUEST, "Invalid email or password");
    }

    if (!user.emailVerified) {
      throw new HttpException(StatusCodes.FORBIDDEN, "Please verify your email before logging in");
    }

    const accessToken = await generateJwtToken(user.id, "access");
    const refreshToken = await generateJwtToken(user.id, "refresh");

    return { accessToken, refreshToken }
  }

  public refreshToken = async (dto: RefreshTokenDTO) => {
    const { refreshToken } = dto;
    const payload = await verifyToken(refreshToken) as JwtPayload;
    if (!payload) {
      throw new HttpException(StatusCodes.BAD_REQUEST, "Invalid token");
    }

    const isBlacklisted = await redisClient.get(`blacklist:${refreshToken}`);
    if (isBlacklisted) {
      throw new HttpException(StatusCodes.BAD_REQUEST, "Token has been revoked");
    }

    const user = await prisma.user.findUnique({
      where: { id: payload.userId }
    });

    if (!user) {
      throw new HttpException(StatusCodes.BAD_REQUEST, "Invalid token");
    }

    const accessToken = await generateJwtToken(user.id, "access");
    return { accessToken }
  }

  public requestPasswordReset = async (dto: RequestPasswordResetDTO) => {
    const { email } = dto;
    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      throw new HttpException(StatusCodes.BAD_REQUEST, "No active account found with that email");
    }

    const code = await this.generateAndStoreOTP(email, OTP_TYPES.PASSWORD_RESET, user.id);
    await this.mailService.sendEmailOTP(email, code, OTP_TYPES.PASSWORD_RESET);
  }

  public validatePasswordResetCode = async (dto: ValidatePasswordResetDTO) => {
    const { code, email } = dto;
    await this.verifyOTPCode(code, email, OTP_TYPES.PASSWORD_RESET);

    const resetToken = await this.generateAndStoreResetToken(email);
    return { resetToken };
  }

  public resetPassword = async (dto: ResetPasswordDTO) => {
    const { resetToken, password } = dto;
    const storedEmail = await redisClient.get(`resetToken:${resetToken}`);
    if (!storedEmail) {
      throw new HttpException(StatusCodes.BAD_REQUEST, "Invalid reset token");
    }

    const user = await prisma.user.findUnique({
      where: { email: storedEmail }
    });

    if (!user) {
      throw new HttpException(StatusCodes.BAD_REQUEST, "No active account with provided email");
    }

    const passwordHash = await hashPassword(password);
    if (!passwordHash) {
      throw new HttpException(StatusCodes.INTERNAL_SERVER_ERROR,
        "There was an issue resetting your password, please try again")
    }

    await prisma.user.update({
      where: { email: storedEmail },
      data: {
        password: passwordHash
      }
    });

    await redisClient.del(`resetToken:${resetToken}`);
  }

  public logout = async (dto: RefreshTokenDTO) => {
    const { refreshToken } = dto;
    const token = await verifyToken(refreshToken) as JwtPayload;
    if (!token) {
      throw new HttpException(StatusCodes.BAD_REQUEST, "Invalid token");
    }

    const currentTime = Math.floor(Date.now() / 1000);
    const expiryTime = token.exp || currentTime + 86400;
    const ttl = expiryTime - currentTime;

    if (ttl > 0) {
      await redisClient.setex(`blacklist:${refreshToken}`, ttl, 'revoked');
    }
  }
}
