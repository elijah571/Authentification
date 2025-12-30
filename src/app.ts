import express from 'express';
import cookieParser from 'cookie-parser';
import authRoute from './routes/auth.route';
import userRouter from './routes/user.routes';
import adminRouter from './routes/admin.routes';
export const app = express();

app.use(express.json());
app.use(cookieParser());

app.get('/health', (_req, res) => {
  res.send('health checked');
});

app.use('/api/auth', authRoute);
app.use('/api/user', userRouter);
app.use('/api/admin', adminRouter);
