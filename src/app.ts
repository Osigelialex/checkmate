import "reflect-metadata";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import { notFoundMiddleware, errorMiddleware } from "./middlewares/error.middleware";
import { v1Router } from "./routes/index.routes";

const app = express();

app.use(cors());
app.use(helmet());
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('short'))

app.use('/api/v1', v1Router);

app.use(notFoundMiddleware);
app.use(errorMiddleware);

export default app;