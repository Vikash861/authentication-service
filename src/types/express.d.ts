import { IUser } from "../models/User.ts";
import { Request } from "express";

declare module 'express-server-static-core' {
    interface Request {
        user?: IUser;
    }
}