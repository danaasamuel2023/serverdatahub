// middleware/middleware.js - Updated for unified user system with roles
const { SystemSettings, BorisUser } = require('../schema/schema');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// JWT Secret - KEEPING YOUR ORIGINAL CONFIGURATION
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
if (!JWT_SECRET && process.env.NODE_ENV === 'production') {
  throw new Error('JWT_SECRET must be set in production environment');
}

const SECRET_KEY = JWT_SECRET || (process.env.NODE_ENV === 'development' ? 'dev-secret-key-change-in-production' : undefined);

// ============================================
// AUTHENTICATE USER (UPDATED)
// ============================================
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const bearerToken = authHeader && authHeader.startsWith('Bearer ') 
      ? authHeader.substring(7) 
      : null;
    
    const token = bearerToken || req.headers['x-auth-token'];
    
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Verify JWT token
    const decoded = jwt.verify(token, SECRET_KEY);
    
    if (!decoded.userId) {
      return res.status(401).json({
        success: false,
        message: 'Invalid token structure'
      });
    }
    
    const user = await BorisUser.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }
    
    if (user.isDisabled) {
      return res.status(403).json({
        success: false,
        message: 'Account has been disabled',
        disableReason: user.disableReason
      });
    }
    
    // Handle legacy users without role
    if (!user.role) {
      user.role = 'user';
      await user.save();
    }
    
    req.user = user;
    req.userId = user._id.toString();
    req.userRole = user.role;
    next();
  } catch (error) {
    console.error('Auth error:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid authentication token'
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Authentication token has expired'
      });
    }
    
    return res.status(401).json({
      success: false,
      message: 'Authentication failed'
    });
  }
};

// ============================================
// ADMIN AUTHENTICATION (UPDATED FOR UNIFIED SYSTEM)
// ============================================
const adminAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.startsWith('Bearer ') 
      ? authHeader.substring(7) 
      : null;
    
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Admin authentication token is required'
      });
    }
    
    // Verify the JWT token
    let decoded;
    try {
      decoded = jwt.verify(token, SECRET_KEY);
    } catch (jwtError) {
      if (jwtError.name === 'JsonWebTokenError') {
        return res.status(401).json({
          success: false,
          message: 'Invalid token'
        });
      }
      if (jwtError.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          message: 'Token has expired'
        });
      }
      throw jwtError;
    }
    
    // Get user
    const user = await BorisUser.findById(decoded.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }
    
    if (user.isDisabled) {
      return res.status(403).json({
        success: false,
        message: 'Account is disabled'
      });
    }
    
    // Handle legacy users without role
    if (!user.role) {
      user.role = 'user';
      await user.save();
    }
    
    // Check if user has admin privileges
    const adminRoles = ['super_admin', 'admin', 'support'];
    if (!adminRoles.includes(user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Admin access required',
        currentRole: user.role
      });
    }
    
    req.adminId = user._id.toString();
    req.admin = user;
    req.adminRole = user.role;
    req.isAdmin = true;
    req.user = user;
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    next();
  } catch (error) {
    console.error('Admin auth error:', error);
    
    return res.status(401).json({
      success: false,
      message: 'Admin authentication failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// ============================================
// ROLE-BASED ACCESS CONTROL (UPDATED)
// ============================================
const requireRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(403).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    const userRole = req.user.role || 'user';
    
    // Super admin can access everything
    if (userRole === 'super_admin') {
      return next();
    }
    
    // Check if the user's role is in the allowed roles
    if (!allowedRoles.includes(userRole)) {
      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions',
        required: allowedRoles,
        current: userRole
      });
    }
    
    next();
  };
};

// ============================================
// PERMISSION-BASED ACCESS CONTROL (NEW)
// ============================================
const requirePermission = (permission) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(403).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Check if user has the specific permission method
    if (req.user.hasPermission && !req.user.hasPermission(permission)) {
      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions',
        required: permission
      });
    }
    
    next();
  };
};

// ============================================
// LOAD SYSTEM SETTINGS (FIXED FOR VALIDATION)
// ============================================
const loadSystemSettings = async (req, res, next) => {
  try {
    let settings = await SystemSettings.findOne({ settingKey: 'MAIN_SETTINGS' })
      .select('+payment.paystack.secretKey +payment.paystack.webhookSecret +providers.geonectech.apiKey +providers.telecel.apiKey +providers.fgamail.apiKey');
    
    if (!settings) {
      // Create with placeholder values that will pass validation
      const defaultSettings = new SystemSettings({
        settingKey: 'MAIN_SETTINGS',
        payment: {
          paystack: {
            publicKey: process.env.PAYSTACK_PUBLIC_KEY || 'pk_test_xxxxxxxxxxxxxxxxxxxxx',
            secretKey: process.env.PAYSTACK_SECRET_KEY || 'sk_test_xxxxxxxxxxxxxxxxxxxxx',
            webhookSecret: process.env.PAYSTACK_WEBHOOK_SECRET || 'whsec_xxxxxxxxxxxxxxxxxxxxx',
            testMode: process.env.NODE_ENV !== 'production'
          },
          processingFees: {
            enabled: true,
            percentage: 1.5,
            fixed: 0,
            whoPays: 'customer',
            minimumDeposit: 5,
            maximumDeposit: 5000
          }
        },
        providers: {
          geonectech: {
            enabled: true,
            apiKey: process.env.GEONECTECH_API_KEY || '',
            apiSecret: process.env.GEONECTECH_SECRET || '',
            baseUrl: process.env.GEONECTECH_BASE_URL || 'https://testhub.geonettech.site/api/v1'
          },
          telecel: {
            enabled: true,
            apiKey: process.env.TELECEL_API_KEY || '8ef44b516735ec9455c4647ae980b445b3bc0be06e5a6095088eaa9cfbeb117e',
            baseUrl: process.env.TELECEL_BASE_URL || 'https://iget.onrender.com/api/developer'
          },
          fgamail: {
            enabled: true,
            apiKey: process.env.FGAMAIL_API_KEY || '806fc6649c0a9597925dd0339c9b3cd6f7994ba3',
            baseUrl: process.env.FGAMAIL_BASE_URL || 'https://fgamall.com/api/v1'
          },
          manual: {
            enabled: true
          }
        },
        security: {
          passwordMinLength: 6,
          maxLoginAttempts: 5,
          lockoutDuration: 30,
          sessionTimeout: 60
        },
        general: {
          siteName: 'DataHub Ghana',
          supportEmail: process.env.SUPPORT_EMAIL || 'support@datahubghana.com',
          supportPhone: process.env.SUPPORT_PHONE || '+233000000000',
          currency: 'GHS',
          maintenanceMode: false
        }
      });
      
      try {
        await defaultSettings.save();
        req.systemSettings = defaultSettings;
      } catch (saveError) {
        console.error('Failed to save default settings:', saveError);
        // Continue without settings in development
        if (process.env.NODE_ENV === 'development') {
          req.systemSettings = null;
        } else {
          throw saveError;
        }
      }
      
      return next();
    }
    
    if (settings.general && settings.general.maintenanceMode && !req.path.includes('/admin')) {
      return res.status(503).json({
        success: false,
        message: 'System is under maintenance. Please try again later.'
      });
    }
    
    req.systemSettings = settings;
    next();
  } catch (error) {
    console.error('Error loading system settings:', error);
    if (process.env.NODE_ENV === 'development') {
      // Continue without settings in development
      req.systemSettings = null;
      next();
    } else {
      return res.status(500).json({
        success: false,
        message: 'System configuration error'
      });
    }
  }
};

// ============================================
// VALIDATE PAYMENT REQUEST
// ============================================
const validatePaymentRequest = async (req, res, next) => {
  try {
    const { amount } = req.body;
    const settings = req.systemSettings;
    
    if (!amount || isNaN(amount)) {
      return res.status(400).json({
        success: false,
        message: 'Valid amount is required'
      });
    }
    
    const numAmount = parseFloat(amount);
    
    if (numAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Amount must be greater than zero'
      });
    }
    
    if (settings && settings.payment && settings.payment.processingFees) {
      const fees = settings.payment.processingFees;
      
      if (numAmount < fees.minimumDeposit) {
        return res.status(400).json({
          success: false,
          message: `Minimum deposit is GHS ${fees.minimumDeposit}`
        });
      }
      
      if (numAmount > fees.maximumDeposit) {
        return res.status(400).json({
          success: false,
          message: `Maximum deposit is GHS ${fees.maximumDeposit}`
        });
      }
    }
    
    const userId = req.userId || req.body.userId;
    if (!userId) {
      return res.status(400).json({
        success: false,
        message: 'User ID is required'
      });
    }
    
    const user = await BorisUser.findById(userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    if (user.isDisabled) {
      return res.status(403).json({
        success: false,
        message: 'Account is disabled'
      });
    }
    
    req.paymentUser = user;
    req.paymentAmount = numAmount;
    next();
  } catch (error) {
    console.error('Payment validation error:', error);
    return res.status(500).json({
      success: false,
      message: 'Payment validation failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// ============================================
// VERIFY WEBHOOK SIGNATURE
// ============================================
const verifyWebhookSignature = (req, res, next) => {
  try {
    const settings = req.systemSettings;
    
    if (!settings || !settings.payment || !settings.payment.paystack) {
      if (process.env.NODE_ENV === 'production') {
        return res.status(500).json({
          success: false,
          message: 'Webhook configuration error'
        });
      }
      console.log('⚠️ Webhook signature verification skipped - settings not loaded');
      return next();
    }
    
    const signature = req.headers['x-paystack-signature'];
    
    if (!signature && process.env.NODE_ENV !== 'production') {
      console.log('⚠️ Webhook signature verification skipped in development');
      return next();
    }
    
    if (!signature) {
      return res.status(400).json({
        success: false,
        message: 'Webhook signature missing'
      });
    }
    
    const bodyString = req.body instanceof Buffer 
      ? req.body.toString() 
      : JSON.stringify(req.body);
    
    const secret = settings.payment.paystack.webhookSecret || 
                   settings.payment.paystack.secretKey;
    
    if (!secret) {
      return res.status(500).json({
        success: false,
        message: 'Webhook secret not configured'
      });
    }
    
    const hash = crypto
      .createHmac('sha512', secret)
      .update(bodyString)
      .digest('hex');
    
    if (hash !== signature) {
      return res.status(400).json({
        success: false,
        message: 'Invalid webhook signature'
      });
    }
    
    if (req.body instanceof Buffer) {
      req.body = JSON.parse(bodyString);
    }
    
    next();
  } catch (error) {
    console.error('Webhook verification error:', error);
    return res.status(500).json({
      success: false,
      message: 'Webhook verification failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// ============================================
// RATE LIMITING
// ============================================
const rateLimitMap = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [key, value] of rateLimitMap.entries()) {
    if (now > value.resetTime) {
      rateLimitMap.delete(key);
    }
  }
}, 60000);

const rateLimit = (options = {}) => {
  const {
    windowMs = 15 * 60 * 1000,
    max = 100,
    message = 'Too many requests, please try again later',
    skipSuccessfulRequests = false,
    keyGenerator = (req) => req.ip || req.userId || 'global'
  } = options;
  
  return (req, res, next) => {
    const key = keyGenerator(req);
    const now = Date.now();
    
    if (!rateLimitMap.has(key)) {
      rateLimitMap.set(key, { count: 1, resetTime: now + windowMs });
      return next();
    }
    
    const limit = rateLimitMap.get(key);
    
    if (now > limit.resetTime) {
      limit.count = 1;
      limit.resetTime = now + windowMs;
      return next();
    }
    
    if (limit.count >= max) {
      const retryAfter = Math.ceil((limit.resetTime - now) / 1000);
      
      res.setHeader('Retry-After', retryAfter);
      res.setHeader('X-RateLimit-Limit', max);
      res.setHeader('X-RateLimit-Remaining', 0);
      res.setHeader('X-RateLimit-Reset', new Date(limit.resetTime).toISOString());
      
      return res.status(429).json({
        success: false,
        message,
        retryAfter
      });
    }
    
    limit.count++;
    
    res.setHeader('X-RateLimit-Limit', max);
    res.setHeader('X-RateLimit-Remaining', max - limit.count);
    res.setHeader('X-RateLimit-Reset', new Date(limit.resetTime).toISOString());
    
    next();
  };
};

// ============================================
// ASYNC HANDLER
// ============================================
const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// ============================================
// ERROR HANDLER
// ============================================
const errorHandler = (err, req, res, next) => {
  if (process.env.NODE_ENV === 'development') {
    console.error('Error Stack:', err.stack);
  } else {
    console.error('Error:', err.message);
  }
  
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(e => e.message);
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors
    });
  }
  
  if (err.code === 11000) {
    const field = Object.keys(err.keyPattern || err.keyValue || {})[0];
    return res.status(400).json({
      success: false,
      message: `${field} already exists`
    });
  }
  
  if (err.name === 'CastError') {
    return res.status(400).json({
      success: false,
      message: 'Invalid ID format'
    });
  }
  
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      message: 'Invalid token'
    });
  }
  
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      message: 'Token expired'
    });
  }
  
  const isDevelopment = process.env.NODE_ENV === 'development';
  const statusCode = err.status || err.statusCode || 500;
  
  res.status(statusCode).json({
    success: false,
    message: err.message || 'Internal server error',
    ...(isDevelopment && { 
      stack: err.stack,
      error: err 
    })
  });
};

// ============================================
// EXPORT ALL MIDDLEWARE
// ============================================
module.exports = {
  loadSystemSettings,
  authenticate,
  adminAuth,
  requireRole,
  requirePermission,
  validatePaymentRequest,
  verifyWebhookSignature,
  rateLimit,
  asyncHandler,
  errorHandler
};