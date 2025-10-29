import { StatusCodes } from "http-status-codes";
import { prisma } from "../config/db.config";
import { LoginDTO, RefreshTokenDTO, SignupDTO, VerifyOtpDTO } from "../dtos/auth.dto";
import { HttpException } from "../utils/exception.util";
import { redisClient } from "../config/redis.config";
import otpGenerator from "otp-generator";
import { MailService } from "./mail.service";
import { generateJwtToken, verifyToken } from "../utils/helpers.utils";
import { hashPassword, compareHashedPassword } from "../utils/helpers.utils";
import { OTP_TYPES } from "../utils/constants.util";
import { JwtPayload } from "jsonwebtoken";

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

    await this.mailService.sendEmailVerificationOtp(email, code);
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
