import { PORT } from "./config";
import { logger } from "./config/logger.config";
import app from "./app";

app.listen(PORT, () => {
  logger.info(`⚡Server running on ${PORT}`);
});
