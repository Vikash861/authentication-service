import mongoose from 'mongoose';

const connectDB = async (DATABASE_URL: string): Promise<void> => {
  try {
    const DB_OPTIONS = {
      dbName: "authentication",
      useNewUrlParser: true,
      useUnifiedTopology: true,
    }
    await mongoose.connect(DATABASE_URL, DB_OPTIONS)
    console.log('Connected Successfully...')
  } catch (error: unknown) {
    if (error instanceof Error) {
      console.error(`Database connection failed: ${error.message}`);
      console.error(`Stack trace: ${error.stack}`);
      console.error('Unknown error occurred during database connection');
    }
  }
}
export default connectDB