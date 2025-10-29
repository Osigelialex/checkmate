import { Router } from "express";
import authRouter from "./v1/auth.routes";

const v1Router = Router();

v1Router.use("/auth", authRouter);

export { v1Router }