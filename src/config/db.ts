import mongoose from 'mongoose';
import dotenv from 'dotenv';
dotenv.config();
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  throw new Error('mongodb is not defined');
}

export const connectToDB = async () => {
  try {
    const conn = await mongoose.connect(MONGODB_URI);
    console.log('MongoDB connected successfully');
  } catch (error: unknown) {
    console.log('error connecting to data base', error);
    process.exit(1);
  }
};
