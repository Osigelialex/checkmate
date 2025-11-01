import { logger } from "../config/logger.config"

export class MailService {
  // TODO: Implement mail service with zepto mail
  constructor() {}

  public sendEmailOTP = async (email: string, code: string, reason: string): Promise<void> => {
    logger.info(`${email} - ${code} - ${reason}`);
  }
}
