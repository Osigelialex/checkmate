import winston from "winston";
import { NODE_ENV } from ".";

export const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ]
});

if (NODE_ENV === 'development') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}