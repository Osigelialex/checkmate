import { Request, Response, NextFunction } from "express";
import { plainToInstance } from "class-transformer";
import { validate } from "class-validator";
import { ValidationError } from "../utils/exception.util";

export const validateDto = (dtoClass: any) => {
  return async (request: Request, response: Response, next: NextFunction) => {
    if (!request.body || typeof request.body !== "object") {
      request.body = {};
    }

    const dto = plainToInstance(dtoClass, request.body);
    const errors = await validate(dto);

    if (errors.length > 0) {
      const errorMessages = errors.map((error) => {
        const constraints = error.constraints;
        return constraints ? Object.values(constraints) : [];
      }).flat();

      throw new ValidationError(errorMessages);
    }

    request.body = dto;
    next();
  }
}