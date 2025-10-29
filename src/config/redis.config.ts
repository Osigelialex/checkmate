import Redis from "ioredis";
import { REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_MODE } from ".";

export const redisClient = REDIS_MODE === 'cluster' ? 
  new Redis.Cluster([
  {
    host: REDIS_HOST,
    port: parseInt(REDIS_PORT!)
  }
]) : new Redis({
  port: parseInt(REDIS_PORT!),
  host: REDIS_HOST,
  db: parseInt(REDIS_DB!)
});
