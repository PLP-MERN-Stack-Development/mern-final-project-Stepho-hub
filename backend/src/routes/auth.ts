import { Router } from 'express';
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { UserModel, ProfileModel } from '../models';

const router = Router();

// Middleware to verify JWT
const authenticateToken = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: { message: 'Access token required' } });
    }

    // Verify the JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;

    // Find user in database
    const user = await UserModel.findById(decoded.userId);
    if (!user) {
      return res.status(403).json({ error: { message: 'User not found' } });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(403).json({ error: { message: 'Authentication failed' } });
  }
};

// Login route
router.post('/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: { message: 'Email and password are required' } });
    }

    // Find user
    const user = await UserModel.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: { message: 'Invalid credentials' } });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: { message: 'Invalid credentials' } });
    }

    // Check if email is verified
    if (!user.emailVerified) {
      return res.status(403).json({
        error: {
          message: 'Please verify your email before logging in',
          requiresVerification: true
        }
      });
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET!,
      { expiresIn: '7d' }
    );

    res.json({
      data: {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          emailVerified: user.emailVerified
        },
        token
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: { message: 'Login failed' } });
  }
});

// Signup route
router.post('/signup', async (req: Request, res: Response) => {
  try {
    const { name, email, password, role = 'patient' } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: { message: 'Name, email, and password are required' } });
    }

    // Check if user already exists
    const existingUser = await UserModel.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: { message: 'User already exists' } });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate email verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Create user
    const user = new UserModel({
      name,
      email,
      password: hashedPassword,
      role,
      emailVerified: false,
      emailVerificationToken: verificationToken,
      emailVerificationExpires: verificationExpires
    });
    await user.save();

    // Create profile
    const profile = new ProfileModel({
      user: user._id,
      name,
      role
    });
    await profile.save();

    // TODO: Send verification email (implement email service)
    // For now, just return success with verification message
    console.log(`Verification token for ${email}: ${verificationToken}`);

    res.status(201).json({
      data: {
        message: 'Account created successfully. Please check your email to verify your account.',
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          emailVerified: false
        }
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: { message: 'Signup failed' } });
  }
});

// Get current user
router.get('/me', authenticateToken, async (req: Request, res: Response) => {
  try {
    res.json({
      data: {
        id: req.user._id,
        name: req.user.name,
        email: req.user.email,
        role: req.user.role,
        emailVerified: req.user.emailVerified
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: { message: 'Failed to get user' } });
  }
});

// Email verification
router.post('/verify-email', async (req: Request, res: Response) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: { message: 'Verification token is required' } });
    }

    // Find user with matching verification token
    const user = await UserModel.findOne({
      emailVerificationToken: token,
      emailVerificationExpires: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).json({ error: { message: 'Invalid or expired verification token' } });
    }

    // Update user as verified
    user.emailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();

    res.json({
      data: {
        message: 'Email verified successfully',
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          emailVerified: true
        }
      }
    });
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({ error: { message: 'Email verification failed' } });
  }
});

// Resend verification email
router.post('/resend-verification', async (req: Request, res: Response) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: { message: 'Email is required' } });
    }

    const user = await UserModel.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: { message: 'User not found' } });
    }

    if (user.emailVerified) {
      return res.status(400).json({ error: { message: 'Email is already verified' } });
    }

    // Generate new verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    user.emailVerificationToken = verificationToken;
    user.emailVerificationExpires = verificationExpires;
    await user.save();

    // TODO: Send verification email
    console.log(`New verification token for ${email}: ${verificationToken}`);

    res.json({
      data: {
        message: 'Verification email sent successfully'
      }
    });
  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({ error: { message: 'Failed to resend verification email' } });
  }
});

// Forgot password
router.post('/forgot-password', async (req: Request, res: Response) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: { message: 'Email is required' } });
    }

    const user = await UserModel.findOne({ email });
    if (!user) {
      // Don't reveal if email exists or not for security
      return res.json({
        data: {
          message: 'If an account with this email exists, a password reset link has been sent.'
        }
      });
    }

    // Generate password reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    user.passwordResetToken = resetToken;
    user.passwordResetExpires = resetExpires;
    await user.save();

    // TODO: Send password reset email
    console.log(`Password reset token for ${email}: ${resetToken}`);

    res.json({
      data: {
        message: 'If an account with this email exists, a password reset link has been sent.'
      }
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: { message: 'Failed to process password reset request' } });
  }
});

// Reset password
router.post('/reset-password', async (req: Request, res: Response) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({ error: { message: 'Token and password are required' } });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: { message: 'Password must be at least 6 characters long' } });
    }

    // Find user with matching reset token
    const user = await UserModel.findOne({
      passwordResetToken: token,
      passwordResetExpires: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).json({ error: { message: 'Invalid or expired reset token' } });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update user password and clear reset token
    user.password = hashedPassword;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    res.json({
      data: {
        message: 'Password reset successfully'
      }
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: { message: 'Failed to reset password' } });
  }
});

export default router;