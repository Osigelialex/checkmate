import { StatusCodes } from "http-status-codes";

export class HttpException extends Error {
  status: number;
  message: string;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export class ValidationError extends HttpException {
  errors: string[]

  constructor(errors: string[]) {
    super(StatusCodes.BAD_REQUEST, "Data validation error");
    this.errors = errors;
  }
}
