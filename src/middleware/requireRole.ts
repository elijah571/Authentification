import { Request, Response, NextFunction } from 'express';

export function requireRole(role: 'user' | 'admin') {
  return (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as any;
    const authUser = authReq.user;
    if (!authUser) {
      return res.status(401).json({ message: 'You are not authenticated' });
    }
    if (authUser.role !== role) {
      return res.status(403).json({ message: 'Unauthorized access' });
    }
    next();
  };
}
