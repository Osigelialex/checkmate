import { StatusCodes } from "http-status-codes";
import { AuthService } from "../services/auth.service";
import { Request, Response } from "express";

export class AuthController {
  private readonly service: AuthService = new AuthService();

  public signUp = async (request: Request, response: Response) => {
    await this.service.signUp(request.body);
    return response.status(StatusCodes.CREATED).json({
      success: true,
      message: 'Sign up successful, please check your email for a verification OTP',
      data: {}
    })
  }

  public verifyOTP = async (request: Request, response: Response) => {
    const responseData = await this.service.verifyOTP(request.body);
    return response.status(StatusCodes.OK).json({
      success: true,
      message: 'OTP verified successfully',
      data: responseData
    }) 
  }

  public login = async (request: Request, response: Response) => {
    const responseData = await this.service.login(request.body);
    return response.status(StatusCodes.OK).json({
      success: true,
      message: 'Login successful',
      data: responseData
    });
  }

  public refreshToken = async (request: Request, response: Response) => {
    const responseData = await this.service.refreshToken(request.body);
    return response.status(StatusCodes.OK).json({
      success: true,
      message: 'Token refreshed successfully',
      data: responseData
    });
  }

  public requestPasswordReset = async (request: Request, response: Response) => {
    await this.service.requestPasswordReset(request.body);
    return response.status(StatusCodes.OK).json({
      success: true,
      message: 'Password reset email sent',
      data: {}
    })
  }

  public validatePasswordReset = async (request: Request, response: Response) => {
    const responseData = await this.service.validatePasswordResetCode(request.body);
    return response.status(StatusCodes.OK).json({
      success: true,
      message: 'Password reset validated',
      data: responseData
    })
  }

  public resetPassword = async (request: Request, response: Response) => {
    const responseData = await this.service.resetPassword(request.body);
    return response.status(StatusCodes.OK).json({
      success: true,
      message: "Password reset successfully",
      data: responseData
    })
  }

  public logout = async (request: Request, response: Response) => {
    await this.service.logout(request.body);
    return response.status(StatusCodes.OK).json({
      success: true,
      message: 'Logged out successfully',
      data: {}
    });
  }
}
