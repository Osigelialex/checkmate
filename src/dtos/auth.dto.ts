import { IsString, IsNotEmpty, IsEmail, Matches, IsJWT, MinLength, IsUUID } from "class-validator";

export class SignupDTO {
  @IsString()
  @IsNotEmpty()
  firstName: string;

  @IsString()
  @IsNotEmpty()
  lastName: string;

  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/, {
    message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
  })
  password: string;
}

export class LoginDTO {
  @IsEmail()
  email: string;

  @IsNotEmpty()
  password: string;
}

export class VerifyOtpDTO {
  @IsString()
  @IsNotEmpty()
  code: string;

  @IsEmail()
  email: string;
}

export class RequestPasswordResetDTO {
  @IsEmail()
  email: string;
}

export class ValidatePasswordResetDTO {
  @IsString()
  @MinLength(6, { message: "Code must be exactly 6 characters long" })
  code: string;

  @IsEmail()
  email: string;
}

export class ResetPasswordDTO {
  @IsUUID()
  resetToken: string;

  @IsString()
  @IsNotEmpty()
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/, {
    message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
  })
  password: string;
}

export class RefreshTokenDTO {
  @IsJWT()
  refreshToken: string;
}