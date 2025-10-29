import dotenv from "dotenv";
dotenv.config();

export const {
  PORT,
  NODE_ENV,
  JWT_SECRET,
  REDIS_PORT,
  REDIS_HOST,
  REDIS_DB,
  REDIS_MODE,
  SALT_ROUNDS
} = process.env;