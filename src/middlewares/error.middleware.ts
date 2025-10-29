import { StatusCodes } from "http-status-codes";
import { HttpException, ValidationError } from "../utils/exception.util";
import { Request, Response, NextFunction } from "express";
import { logger } from "../config/logger.config";

export const errorMiddleware = (
  error: HttpException,
  request: Request,
  response: Response,
  next: NextFunction
) => {
  if (error instanceof ValidationError) {
    logger.error("Data validation error", error.errors);
    return response.status(StatusCodes.BAD_REQUEST).json({
      success: false,
      message: 'Data validation error',
      errors: error.errors
    });
  }

  return response.status(error.status || StatusCodes.INTERNAL_SERVER_ERROR).json({
    success: false,
    message: error.message || 'Something went wrong, please try again later',
    errors: {}
  });
}

export const notFoundMiddleware = (
  request: Request,
  response: Response,
  next: NextFunction
) => {
  logger.error("Resource not found");
  return response.status(StatusCodes.NOT_FOUND).json({
    success: false,
    message: 'Resource not found',
    errors: {}
  })
}