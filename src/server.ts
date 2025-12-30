import dotenv from 'dotenv';
import http from 'http';
import { app } from './app';
import { connectToDB } from './config/db';

dotenv.config();

async function startServer() {
  await connectToDB();
  const server = http.createServer(app);
  server.listen(process.env.PORT, () => {
    console.log(`Server is listening on port: ${process.env.PORT}`);
  });
}

startServer();
