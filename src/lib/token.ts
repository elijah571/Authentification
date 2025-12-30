import jwt from 'jsonwebtoken';

export function createAccessToken(
  userId: string,
  role: 'user' | 'admin',
  tokenVersion: number
) {
  return jwt.sign(
    { sub: userId, role, tokenVersion },
    process.env.JWT_ACCESS_SECRET!,
    { expiresIn: '30m' }
  );
}

export function verifyAccessToken(token: string) {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
    sub: string;
    role: 'user' | 'admin';
    tokenVersion: number;
  };
}

export function createRefreshToken(userId: string, tokenVersion: number) {
  return jwt.sign(
    { sub: userId, tokenVersion },
    process.env.JWT_REFRESH_SECRET!,
    { expiresIn: '7d' }
  );
}

export function verifyRefreshToken(token: string) {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET!) as {
    sub: string;
    tokenVersion: number;
  };
}
