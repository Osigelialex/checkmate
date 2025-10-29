import { Request, Response, NextFunction } from "express";
import { HttpException } from "../utils/exception.util";
import { StatusCodes } from "http-status-codes";
import { prisma } from "../config/db.config";

export const hasPermission = (permission: string, sessionId: string) => {
  return async (request: Request, response: Response, next: NextFunction) => {
    const user = request.user;
    
    if (!user) {
      throw new HttpException(StatusCodes.UNAUTHORIZED, "Authentication required to access this resource");
    }

    const hasPermission = await prisma.sessionUserRole.findFirst({
      where: {
        userId: user.id,
        sessionId: sessionId,
        role: {
          permissions: {
            some: {
              name: permission
            }
          }
        }
      },
    });

    if (!hasPermission) {
      throw new HttpException(StatusCodes.FORBIDDEN, "You are not authorized to access this resource");
    }

    next();
  }
}
