import { JWT_SECRET, SALT_ROUNDS } from "../config";
import jwt, { JwtPayload } from "jsonwebtoken";
import { logger } from "../config/logger.config";
import bcrypt from "bcrypt";

type TokenVariation = "access" | "refresh";

export const generateJwtToken = (userId: string, variation: TokenVariation): Promise<string | undefined | null> => {
  return new Promise((resolve) => {
    jwt.sign({ userId }, JWT_SECRET!, { expiresIn: variation == "access" ? '15m' : '7d' }, (error: any, token) => {
      if (error) {
        logger.error(`Failed to generate access token: ${error}`);
        resolve(null);
      } else {
        resolve(token);
      }
    });
  })
}

export const verifyToken = (token: string): Promise<string | JwtPayload | undefined | null> => {
  return new Promise((resolve) => {
    jwt.verify(token, JWT_SECRET!, (error, decoded) => {
      if (error) {
        logger.error(`Failed to verify jwt token: ${error}`);
        resolve(null);
      } else {
        resolve(decoded);
      }
    })
  })
}

export const hashPassword = async (password: string): Promise<string | null> => {
  try {
    const passwordHash = await bcrypt.hash(password, parseInt(SALT_ROUNDS!));
    return passwordHash;
  } catch (e: any) {
    logger.error(`An error occurred during password hash: ${e}`);
    return null;
  }
}

export const compareHashedPassword = async (password: string, hash: string): Promise<boolean> => {
  const passwordValid = await bcrypt.compare(password, hash);
  return passwordValid;
}