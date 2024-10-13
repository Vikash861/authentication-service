import dotenv from 'dotenv';
import express, { Application } from 'express';
import cors from 'cors';
import connectDB from './config/connectdb.js';
import userRoutes from './routes/userRoutes.js';
import cookieParser from 'cookie-parser';

dotenv.config();

const app: Application = express();
const port: string | number = process.env.PORT || 3000;
const DATABASE_URL: string = process.env.DATABASE_URL as string;

if (!DATABASE_URL) {
  throw new Error('DATABASE_URL is not defined in the environment variables');
}

app.use(cors());
app.use(cookieParser());

connectDB(DATABASE_URL);

app.use(express.json());

app.use("/api/user", userRoutes);

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});
