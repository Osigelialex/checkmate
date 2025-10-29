import { logger } from "../config/logger.config"

export class MailService {
  constructor() {}

  public sendEmailVerificationOtp = async (email: string, code: string): Promise<void> => {
    // TODO: Implement mail server with zepto mail
    logger.info(`${email} - ${code}`);
  }
}
