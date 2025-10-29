import { Request, Response, NextFunction } from "express";
import { HttpException } from "../utils/exception.util";
import { StatusCodes } from "http-status-codes";
import { verifyToken } from "../utils/helpers.utils";
import { prisma } from "../config/db.config";

export const authMiddleware = async (request: Request, response: Response, next: NextFunction) => {
  const authHeader = request.headers.authorization;
  if (!authHeader) {
    throw new HttpException(StatusCodes.UNAUTHORIZED, "Invalid access token");
  }

  if (!authHeader.startsWith("Bearer")) {
    throw new HttpException(StatusCodes.UNAUTHORIZED, "Invalid access token");
  }

  const accessToken = authHeader.replace("Bearer ", "");
  const decoded = await verifyToken(accessToken) as any;

  if (!decoded) {
    throw new HttpException(StatusCodes.UNAUTHORIZED, "Invalid access token");
  }

  const user = await prisma.user.findUnique({
    where: { id: decoded.userId },
    select: {
      id: true,
      firstName: true,
      lastName: true,
      email: true,
      emailVerified: true,
    }
  });

  if (!user) {
    throw new HttpException(StatusCodes.UNAUTHORIZED, "Invalid access token");
  }

  request.user = user;
  next();
}
