import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { User } from '../models/user.model';
import { loginSchema, registrationSchema } from './auth.schema';
import { checkPassword, hashPassword } from '../lib/hash';
import { sendEmail } from '../lib/email';
import {
  createAccessToken,
  createRefreshToken,
  verifyRefreshToken,
} from '../lib/token';

import crypto from 'crypto';
import { OAuth2Client } from 'google-auth-library';
import { authenticator } from 'otplib';

function getAppUrl() {
  return process.env.APP_URL || `http://localhost:${process.env.PORT}/api`;
}

function getGoogleClient() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = process.env.GOOGLE_REDIRECT_URI;

  if (!clientId || !clientSecret) {
    throw new Error('Google client id and secret both are missing');
  }
  return new OAuth2Client({
    clientId,
    clientSecret,
    redirectUri,
  });
}

export async function registerUser(req: Request, res: Response) {
  try {
    const result = registrationSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({
        message: 'Invalid data',
        errors: result.error.flatten(),
      });
    }

    const { name, email, password } = result.data;
    const normalizedEmail = email.toLowerCase().trim();

    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return res.status(409).json({ message: 'User already exists' });
    }

    const passwordHash = await hashPassword(password);

    const newUser = await User.create({
      name,
      email: normalizedEmail,
      passwordHash,
      role: 'user',
      isEmailVerified: false,
      twoFactorEnabled: false,
    });

    const verifyToken = jwt.sign(
      { sub: newUser.id },
      process.env.JWT_ACCESS_SECRET as string,
      { expiresIn: '1d' }
    );

    const verifyUrl = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`;

    await sendEmail(
      newUser.email,
      'Verify your email',
      `
        <p>Please verify your email by clicking the link below:</p>
        <p><a href="${verifyUrl}">${verifyUrl}</a></p>
      `
    );

    return res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: newUser.id,
        email: newUser.email,
        role: newUser.role,
        isEmailVerified: newUser.isEmailVerified,
      },
    });
  } catch (error) {
    console.error('Register error:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
}

export async function verifyEmailHandler(req: Request, res: Response) {
  const token = req.query.token as string | undefined;

  if (!token) {
    return res.status(400).json({ message: 'Verification token is missing' });
  }

  try {
    const payload = jwt.verify(
      token,
      process.env.JWT_ACCESS_SECRET as string
    ) as { sub: string };

    const user = await User.findById(payload.sub);
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    if (user.isEmailVerified) {
      return res.json({ message: 'Email is already verified' });
    }

    user.isEmailVerified = true;
    await user.save();

    return res.json({ message: 'Email verified successfully. You can login.' });
  } catch (error) {
    console.error('verification error:', error);
    return res.status(500).json({ message: 'Invalid or expired token' });
  }
}

export async function loginHandler(req: Request, res: Response) {
  try {
    const result = loginSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({
        message: 'Invalid data',
        errors: result.error.flatten(),
      });
    }
    const { email, password, twoFactorCode } = result.data;
    const normalizedEmail = email.toLowerCase().trim();

    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    const ok = await checkPassword(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    if (!user.isEmailVerified) {
      return res.status(403).json({ message: 'please verify your email' });
    }

    if (user.twoFactorEnabled) {
      if (!twoFactorCode || typeof twoFactorCode !== 'string') {
        return res.status(400).json({ message: 'Two factor code required' });
      }

      const isValidCode = authenticator.check(
        twoFactorCode,
        user.twoFactorSecret as string
      );

      if (!isValidCode) {
        return res.status(400).json({ message: 'Invalid two factor code' });
      }
    }

    const accessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion
    );
    //verify the code

    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    const isProd = process.env.NODE_ENV === 'production';

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'strict' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: 'Login seccussfully',
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.error('Register error:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
}

export async function refreshTokenHandler(req: Request, res: Response) {
  try {
    const token = req.cookies?.refreshToken as string | undefined;
    if (!token) {
      return res.status(401).json({ message: 'Refresh token missing' });
    }
    const payload = verifyRefreshToken(token);
    const user = await User.findById(payload.sub);
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }
    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({ message: 'Refresh token invalidated' });
    }
    const newAccessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion
    );

    const newRefreshToken = createRefreshToken(user.id, user.tokenVersion);
    const isProd = process.env.NODE_ENV === 'production';

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'strict' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return res.status(200).json({
      message: 'refresh token seccussfully',
      newAccessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.error('refresh error:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
}

export async function logoutHandler(_req: Request, res: Response) {
  res.clearCookie('refreshToken', { path: '/' });
  return res.status(200).json({
    message: 'Logged out',
  });
}

export async function forgotPasswordHandler(req: Request, res: Response) {
  const { email } = req.body as { email?: string };
  if (!email) {
    return res.status(400).json({ message: 'Email is requiredf' });
  }
  const normalizedEmail = email.toLowerCase().trim();
  try {
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.json({
        message:
          'If an account with this email exists, we will send you a reset link',
      });
    }
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto
      .createHash('sha256')
      .update(rawToken)
      .digest('hex');
    user.resetPasswordToken = tokenHash;
    user.resetPasswordTokenExpires = new Date(Date.now() + 15 * 60 * 1000);
    await user.save();
    const resetUrl = `${getAppUrl()}/auth/reset-password?token=${rawToken}`;

    await sendEmail(
      user.email,
      ' Reset your password',

      `<p>
      you requested password reset. Click on the link below to reset    your password
      </P>
      <p><a href="${resetUrl}">${resetUrl}</a></p>`
    );
    return res.json({
      message:
        'If an account with this email exists, we will send you a reset link',
    });
  } catch (error) {
    console.error('forgot password  error:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
}

export async function resetPasswordHandler(req: Request, res: Response) {
  const { token, password } = req.body as { token?: string; password?: string };
  if (!token) {
    return res.status(400).json({ message: 'Reset token is missing' });
  }
  if (!password || password.length < 6) {
    return res
      .status(400)
      .json({ message: 'Password must be atleast 6 char long' });
  }
  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({
      resetPasswordToken: tokenHash,
      resetPasswordTokenExpires: { $gt: new Date() },
    });
    if (!user) {
      return res.status(400).json({ message: 'invalid or expire token' });
    }
    const newPasswordHash = await hashPassword(password);
    user.passwordHash = newPasswordHash;

    user.resetPasswordToken = undefined;
    user.resetPasswordTokenExpires = undefined;
    user.tokenVersion = user.tokenVersion + 1;

    await user.save();
    return res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('forgot password  error:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
}

export async function googleAuthStartHandler(_req: Request, res: Response) {
  try {
    const client = getGoogleClient();
    const url = client.generateAuthUrl({
      access_type: 'offline',
      prompt: 'consent',
      scope: ['openid', 'email', 'profile'],
    });

    return res.redirect(url);
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: 'internal server error' });
  }
}

export async function googleAuthCallbackHandler(req: Request, res: Response) {
  const code = req.query.code as string | undefined;
  if (!code) {
    return res.status(400).json({ message: 'Missing a code in callback' });
  }
  try {
    const client = getGoogleClient();
    const { tokens } = await client.getToken(code);
    console.log(tokens, code, 'code');

    if (!tokens.id_token) {
      return res.status(400).json({ message: 'No google id_token present' });
    }
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID as string,
    });

    const payload = ticket.getPayload();

    const email = payload?.email;
    const emailVerified = payload?.email_verified;

    if (!email || !emailVerified) {
      return res
        .status(400)
        .json({ message: ' google email account  is not verified' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    let user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      const randomPassword = crypto.randomBytes(16).toString('hex');
      const passwordHash = await hashPassword(randomPassword);

      user = await User.create({
        email: normalizedEmail,
        passwordHash,
        role: 'user',
        isEmailVerified: true,
        twoFactorEnabled: false,
      });
    } else {
      if (!user.isEmailVerified) {
        user.isEmailVerified = true;
        await user.save();
      }
    }
    const accessToken = createAccessToken(
      user.id,
      user.role as 'user' | 'admin',
      user.tokenVersion
    );
    const refreshToken = createRefreshToken(user.id, user.tokenVersion);
    const isProd = process.env.NODE_ENV === 'production';

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'strict' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return res.json({
      message: 'Google login successfully',
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: 'internal server error' });
  }
}

export async function twoFASetup(req: Request, res: Response) {
  const authReq = req as any;
  const authUser = authReq.user;

  if (!authUser) {
    return res.status(401).json({
      message: 'Not authenticated',
    });
  }
  try {
    const user = await User.findById(authUser.id);
    if (!user) {
      return res.status(404).json({ message: 'user not found' });
    }
    const secret = authenticator.generateSecret();

    const issuer = 'NodeAdvancedAuthApp';

    const otpAuthUrl = authenticator.keyuri(user.email, issuer, secret);
    user.twoFactorSecret = secret;
    user.twoFactorEnabled = false;

    await user.save();

    return res.json({
      message: ' 2FA setup is done',
      otpAuthUrl,
      secret,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: 'internal server error' });
  }
}

export async function twoFactorVerifyHandler(req: Request, res: Response) {
  const authReq = req as any;
  const authUser = authReq.user;

  if (!authUser) {
    return res.status(401).json({
      message: 'Not authenticated',
    });
  }
  const { code } = req.body as { code?: string };
  if (!code) {
    return res.status(400).json({
      message: ' Two Factor code is required',
    });
  }
  try {
    const user = await User.findById(authUser.id);
    if (!user) {
      return res.status(404).json({ message: 'user not found' });
    }

    if (!user.twoFactorSecret) {
      return res.status(400).json({
        message: "you don't have two factor setu",
      });
    }
    const isValid = authenticator.check(code, user.twoFactorSecret);
    if (!isValid) {
      return res.status(400).json({
        message: 'Invalid two factor code',
      });
    }
    user.twoFactorEnabled = true;
    await user.save();
    return res.json({
      message: '2FA enabled successfully',
      twoFactorEnabled: true,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: 'internal server error' });
  }
}
