// auth.routes.js - Modified for plain text passwords (TEMPORARY - SECURITY RISK)
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const axios = require('axios');

// Import models from updated schemas
const { BorisUser, SystemSettings } = require('../../schema/schema');

// Import middleware
const { asyncHandler, authenticate, rateLimit } = require('../../middleware/middleware');

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
const ARKESEL_API_KEY = process.env.ARKESEL_API_KEY || 'QkNhS0l2ZUZNeUdweEtmYVRUREg';

// ============================================
// HELPER FUNCTIONS
// ============================================

// Generate JWT token with role information
const generateToken = (userId, email, role = 'user') => {
  return jwt.sign(
    { 
      userId, 
      email, 
      role,
      isAdmin: ['admin', 'super_admin', 'support'].includes(role)
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
};

// Send SMS function
const sendSMS = async (phoneNumber, message, options = {}) => {
  const {
    scheduleTime = null,
    useCase = 'transactional',
    senderID = 'DataHubGh'
  } = options;

  // Input validation
  if (!phoneNumber || !message) {
    throw new Error('Phone number and message are required');
  }

  // Base parameters
  const params = {
    action: 'send-sms',
    api_key: ARKESEL_API_KEY,
    to: phoneNumber,
    from: senderID,
    sms: message
  };

  // Add optional parameters
  if (scheduleTime) {
    params.schedule = scheduleTime;
  }

  if (useCase && ['promotional', 'transactional'].includes(useCase)) {
    params.use_case = useCase;
  }

  // Add Nigerian use case if phone number starts with 234
  if (phoneNumber.startsWith('234') && !useCase) {
    params.use_case = 'transactional';
  }

  try {
    const response = await axios.get('https://sms.arkesel.com/sms/api', {
      params,
      timeout: 10000 // 10 second timeout
    });

    // Map error codes to meaningful messages
    const errorCodes = {
      '100': 'Bad gateway request',
      '101': 'Wrong action',
      '102': 'Authentication failed',
      '103': 'Invalid phone number',
      '104': 'Phone coverage not active',
      '105': 'Insufficient balance',
      '106': 'Invalid Sender ID',
      '109': 'Invalid Schedule Time',
      '111': 'SMS contains spam word. Wait for approval'
    };

    if (response.data.code !== 'ok') {
      const errorMessage = errorCodes[response.data.code] || 'Unknown error occurred';
      throw new Error(`SMS sending failed: ${errorMessage}`);
    }

    console.log('SMS sent successfully:', {
      to: phoneNumber,
      status: response.data.code,
      balance: response.data.balance,
      mainBalance: response.data.main_balance
    });

    return {
      success: true,
      data: response.data
    };
  } catch (error) {
    console.error('SMS Error:', error.message);

    // Return failure but don't break the flow
    return {
      success: false,
      error: {
        message: error.message,
        code: error.response?.data?.code,
        details: error.response?.data
      }
    };
  }
};

// Validate Ghana phone number
const validateGhanaPhoneNumber = (phoneNumber) => {
  // Accept formats: +233XXXXXXXXX, 233XXXXXXXXX, 0XXXXXXXXX
  const phoneRegex = /^(?:\+233|233|0)(20|23|24|25|26|27|28|29|30|31|32|50|53|54|55|56|57|58|59)\d{7}$/;
  return phoneRegex.test(phoneNumber);
};

// Format phone number to international format
const formatPhoneNumber = (phoneNumber) => {
  // Remove all non-digit characters
  let cleaned = phoneNumber.replace(/\D/g, '');
  
  // If starts with 0, replace with 233
  if (cleaned.startsWith('0')) {
    cleaned = '233' + cleaned.substring(1);
  }
  
  // If doesn't start with 233, add it
  if (!cleaned.startsWith('233')) {
    cleaned = '233' + cleaned;
  }
  
  return '+' + cleaned;
};

// ============================================
// SIGNUP ROUTE - PLAIN TEXT PASSWORD
// ============================================
router.post('/signup',
  rateLimit({ max: 5, windowMs: 15 * 60 * 1000 }), // 5 attempts per 15 minutes
  asyncHandler(async (req, res) => {
    const { 
      firstName, 
      secondName, 
      email, 
      phoneNumber, 
      business, 
      password,
      role = 'user' // Default role
    } = req.body;

    // Validate required fields
    const missingFields = {};
    if (!firstName) missingFields.firstName = 'First name is required';
    if (!secondName) missingFields.secondName = 'Second name is required';
    if (!email) missingFields.email = 'Email is required';
    if (!phoneNumber) missingFields.phoneNumber = 'Phone number is required';
    if (!business?.name) missingFields.businessName = 'Business name is required';
    if (!password) missingFields.password = 'Password is required';

    if (Object.keys(missingFields).length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields',
        details: missingFields
      });
    }

    // Validate email format
    const emailRegex = /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format',
        details: { email: 'Please enter a valid email address' }
      });
    }

    // Validate and format phone number
    if (!validateGhanaPhoneNumber(phoneNumber)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid phone number',
        details: { phoneNumber: 'Please enter a valid Ghana phone number' }
      });
    }

    const formattedPhoneNumber = formatPhoneNumber(phoneNumber);

    // Validate password strength
    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password too weak',
        details: { password: 'Password must be at least 6 characters long' }
      });
    }

    // Check if user already exists
    const existingUser = await BorisUser.findOne({
      $or: [
        { email: email.toLowerCase() },
        { phoneNumber: formattedPhoneNumber }
      ]
    });

    if (existingUser) {
      const field = existingUser.email === email.toLowerCase() ? 'email' : 'phone number';
      return res.status(409).json({
        success: false,
        message: 'User already exists',
        details: { [field]: `This ${field} is already registered` }
      });
    }

    // Determine business type based on role
    let businessType = 'individual';
    let resellerDiscount = 0;
    
    if (role === 'reseller') {
      businessType = 'reseller';
      resellerDiscount = 10; // Default 10% discount for resellers
    } else if (role === 'admin' || role === 'super_admin') {
      businessType = 'company';
    }

    // Create new user with PLAIN TEXT password
    const newUser = new BorisUser({
      firstName,
      secondName,
      email: email.toLowerCase(),
      phoneNumber: formattedPhoneNumber,
      business: {
        name: business?.name || business,
        address: business?.address || '',
        registrationNumber: business?.registrationNumber || '',
        type: businessType,
        resellerDiscount
      },
      password: password, // PLAIN TEXT - NO HASHING
      role: role,
      permissions: {
        canManageUsers: false,
        canManageOrders: false,
        canManageSettings: false,
        canManageNetworks: false,
        canViewReports: false,
        canProcessManualOrders: false,
        canAdjustWallets: false
      },
      wallet: {
        balance: 0,
        currency: 'GHS',
        transactions: []
      }
    });

    // IMPORTANT: Skip password hashing if your schema has a pre-save hook
    newUser.$skipPasswordHash = true;
    await newUser.save();

    // Generate JWT token with role
    const token = generateToken(newUser._id, newUser.email, newUser.role);

    // Send welcome SMS (don't wait for it)
    const welcomeMessage = `Welcome to DataHubGh, ${firstName}! Your account has been created successfully. Enjoy our services!`;
    sendSMS(formattedPhoneNumber, welcomeMessage).catch(console.error);

    res.status(201).json({
      success: true,
      message: 'Account created successfully',
      token,
      user: {
        id: newUser._id,
        email: newUser.email,
        firstName: newUser.firstName,
        secondName: newUser.secondName,
        phoneNumber: newUser.phoneNumber,
        businessName: newUser.business.name,
        role: newUser.role,
        isAdmin: newUser.isAdmin ? newUser.isAdmin() : false,
        walletBalance: 0
      }
    });
  })
);

// ============================================
// LOGIN ROUTE - PLAIN TEXT PASSWORD
// ============================================
router.post('/login',
  rateLimit({ max: 10, windowMs: 15 * 60 * 1000 }), // 10 attempts per 15 minutes
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Find user by email (include password field which is normally excluded)
    const user = await BorisUser.findOne({ 
      email: email.toLowerCase() 
    }).select('+password +loginAttempts +lockUntil');

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Check if account is locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const minutesLeft = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(423).json({
        success: false,
        message: `Account is locked. Please try again in ${minutesLeft} minutes`
      });
    }

    // Check if user is disabled
    if (user.isDisabled) {
      return res.status(403).json({
        success: false,
        message: 'Account is disabled',
        disableReason: user.disableReason,
        disabledAt: user.disabledAt
      });
    }

    // PLAIN TEXT PASSWORD COMPARISON
    const isPasswordValid = user.password === password;

    if (!isPasswordValid) {
      // Increment login attempts
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      
      // Lock account after 5 failed attempts
      if (user.loginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 30 * 60000); // Lock for 30 minutes
        await user.save();
        
        return res.status(423).json({
          success: false,
          message: 'Account locked due to multiple failed login attempts. Please try again in 30 minutes'
        });
      }
      
      await user.save();
      
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password',
        attemptsRemaining: 5 - user.loginAttempts
      });
    }

    // Reset login attempts and update last login on successful login
    if (user.loginAttempts > 0 || user.lockUntil) {
      user.loginAttempts = 0;
      user.lockUntil = undefined;
    }
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT token with role
    const token = generateToken(user._id, user.email, user.role);

    // Prepare response data
    const userData = {
      id: user._id,
      email: user.email,
      firstName: user.firstName,
      secondName: user.secondName,
      phoneNumber: user.phoneNumber,
      businessName: user.business?.name,
      role: user.role,
      isAdmin: user.isAdmin ? user.isAdmin() : false,
      walletBalance: user.wallet?.balance || 0,
      walletCurrency: user.wallet?.currency || 'GHS'
    };

    // Add permissions for admin users
    if (user.isAdmin && user.isAdmin()) {
      userData.permissions = user.permissions;
    }

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: userData
    });
  })
);

// ============================================
// ADMIN LOGIN ROUTE - PLAIN TEXT PASSWORD
// ============================================
router.post('/admin-login',
  rateLimit({ max: 5, windowMs: 15 * 60 * 1000 }), // Stricter rate limit for admin
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Find user by email
    const user = await BorisUser.findOne({ 
      email: email.toLowerCase() 
    }).select('+password +loginAttempts +lockUntil');

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check if user has admin privileges
    const adminRoles = ['super_admin', 'admin', 'support'];
    if (!adminRoles.includes(user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Admin access required. Your current role is: ' + user.role
      });
    }

    // Check if account is locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const minutesLeft = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(423).json({
        success: false,
        message: `Account is locked. Please try again in ${minutesLeft} minutes`
      });
    }

    // Check if user is disabled
    if (user.isDisabled) {
      return res.status(403).json({
        success: false,
        message: 'Account is disabled',
        disableReason: user.disableReason
      });
    }

    // PLAIN TEXT PASSWORD COMPARISON
    const isPasswordValid = user.password === password;

    if (!isPasswordValid) {
      // Increment login attempts
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      
      // Lock account after 5 failed attempts
      if (user.loginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 30 * 60000);
        await user.save();
        
        return res.status(423).json({
          success: false,
          message: 'Account locked for 30 minutes due to multiple failed attempts'
        });
      }
      
      await user.save();
      
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
        attemptsRemaining: 5 - user.loginAttempts
      });
    }

    // Reset login attempts and update last login
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    user.lastLogin = new Date();
    await user.save();

    // Generate admin token
    const token = generateToken(user._id, user.email, user.role);

    res.json({
      success: true,
      message: 'Admin login successful',
      token,
      admin: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        secondName: user.secondName,
        role: user.role,
        permissions: user.permissions,
        isAdmin: true
      }
    });
  })
);

// ============================================
// VERIFY TOKEN
// ============================================
router.get('/verify',
  authenticate,
  asyncHandler(async (req, res) => {
    const user = await BorisUser.findById(req.userId)
      .select('-password -wallet.transactions');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          secondName: user.secondName,
          email: user.email,
          phoneNumber: user.phoneNumber,
          role: user.role,
          isAdmin: user.isAdmin ? user.isAdmin() : false,
          business: user.business,
          wallet: {
            balance: user.wallet?.balance || 0,
            currency: user.wallet?.currency || 'GHS'
          },
          permissions: user.permissions
        }
      }
    });
  })
);

// ============================================
// CHANGE PASSWORD - PLAIN TEXT
// ============================================
router.post('/change-password',
  authenticate,
  asyncHandler(async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Current password and new password are required'
      });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'New password must be at least 6 characters long'
      });
    }
    
    // Get user with password
    const user = await BorisUser.findById(req.userId).select('+password');
    
    // PLAIN TEXT PASSWORD COMPARISON
    if (user.password !== currentPassword) {
      return res.status(401).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }
    
    // Update with PLAIN TEXT password
    user.password = newPassword;
    user.$skipPasswordHash = true; // Skip hashing if schema has pre-save hook
    user.lastPasswordReset = new Date();
    await user.save();
    
    res.json({
      success: true,
      message: 'Password changed successfully'
    });
  })
);

// ============================================
// PASSWORD RESET ROUTES
// ============================================

// Step 1: Request password reset
router.post('/request-password-reset',
  rateLimit({ max: 3, windowMs: 60 * 60 * 1000 }), // 3 attempts per hour
  asyncHandler(async (req, res) => {
    const { phoneNumber } = req.body;

    if (!phoneNumber) {
      return res.status(400).json({
        success: false,
        message: 'Phone number is required'
      });
    }

    // Validate and format phone number
    if (!validateGhanaPhoneNumber(phoneNumber)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid phone number format'
      });
    }

    const formattedPhoneNumber = formatPhoneNumber(phoneNumber);

    // Find user by phone number
    const user = await BorisUser.findOne({ 
      phoneNumber: formattedPhoneNumber 
    });

    if (!user) {
      // Don't reveal if user exists or not for security
      return res.json({
        success: true,
        message: 'If this phone number is registered, you will receive a reset code via SMS'
      });
    }

    if (user.isDisabled) {
      return res.status(403).json({
        success: false,
        message: 'Account is disabled',
        disableReason: user.disableReason
      });
    }

    // Check if there's a recent OTP request (rate limiting)
    if (user.resetPasswordOTPExpiry && 
        new Date() < user.resetPasswordOTPExpiry && 
        user.resetPasswordOTP) {
      const minutesLeft = Math.ceil((user.resetPasswordOTPExpiry - Date.now()) / 60000);
      return res.status(429).json({
        success: false,
        message: `A reset code was already sent. Please wait ${minutesLeft} minutes before requesting a new one`
      });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Set OTP expiration (10 minutes)
    const otpExpiry = new Date(Date.now() + 10 * 60000);

    // Save OTP to user (these fields are select: false in schema)
    user.resetPasswordOTP = otp;
    user.resetPasswordOTPExpiry = otpExpiry;
    await user.save();

    // Send OTP via SMS
    const message = `Your DataHubGh password reset code is: ${otp}\n\nThis code expires in 10 minutes.\n\nIf you didn't request this, please ignore.`;
    const smsResult = await sendSMS(formattedPhoneNumber, message);

    if (!smsResult.success) {
      console.error('Failed to send OTP:', smsResult.error);
      // Still return success for security
    }

    // Mask phone number for privacy
    const maskedPhone = formattedPhoneNumber.slice(0, 4) + '****' + formattedPhoneNumber.slice(-4);

    res.json({
      success: true,
      message: 'Password reset code sent successfully',
      phoneNumber: maskedPhone,
      expiresIn: '10 minutes'
    });
  })
);

// Step 2: Reset password with OTP
router.post('/reset-password',
  asyncHandler(async (req, res) => {
    const { phoneNumber, otp, newPassword } = req.body;

    // Validate input
    if (!phoneNumber || !otp || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Phone number, OTP, and new password are required'
      });
    }

    // Validate phone number
    if (!validateGhanaPhoneNumber(phoneNumber)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid phone number format'
      });
    }

    const formattedPhoneNumber = formatPhoneNumber(phoneNumber);

    // Validate new password
    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'New password must be at least 6 characters long'
      });
    }

    // Find user with OTP fields
    const user = await BorisUser.findOne({ 
      phoneNumber: formattedPhoneNumber 
    }).select('+resetPasswordOTP +resetPasswordOTPExpiry +password');

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid phone number or OTP'
      });
    }

    // Check if OTP exists
    if (!user.resetPasswordOTP || !user.resetPasswordOTPExpiry) {
      return res.status(400).json({
        success: false,
        message: 'No password reset was requested or it has expired'
      });
    }

    // Check if OTP is expired
    if (new Date() > user.resetPasswordOTPExpiry) {
      // Clear expired OTP
      user.resetPasswordOTP = undefined;
      user.resetPasswordOTPExpiry = undefined;
      await user.save();

      return res.status(400).json({
        success: false,
        message: 'Reset code has expired. Please request a new one'
      });
    }

    // Verify OTP
    if (user.resetPasswordOTP !== otp) {
      return res.status(400).json({
        success: false,
        message: 'Invalid reset code'
      });
    }

    // Update with PLAIN TEXT password
    user.password = newPassword;
    user.$skipPasswordHash = true; // Skip hashing
    
    // Clear OTP data
    user.resetPasswordOTP = undefined;
    user.resetPasswordOTPExpiry = undefined;
    user.lastPasswordReset = new Date();
    
    // Reset any login locks
    user.loginAttempts = 0;
    user.lockUntil = undefined;

    await user.save();

    // Send confirmation SMS
    const message = 'Your DataHubGh password has been successfully reset. If you did not perform this action, please contact support immediately.';
    sendSMS(formattedPhoneNumber, message).catch(console.error);

    res.json({
      success: true,
      message: 'Password reset successful. You can now login with your new password'
    });
  })
);

// ============================================
// PROMOTE USER (Super Admin Only)
// ============================================
router.post('/promote-user',
  authenticate,
  asyncHandler(async (req, res) => {
    const { userId, newRole, resellerDiscount } = req.body;
    
    // Check if current user is super admin
    if (req.user.role !== 'super_admin') {
      return res.status(403).json({
        success: false,
        message: 'Only super admins can promote users'
      });
    }
    
    if (!userId || !newRole) {
      return res.status(400).json({
        success: false,
        message: 'User ID and new role are required'
      });
    }
    
    const validRoles = ['user', 'reseller', 'support', 'admin', 'super_admin'];
    if (!validRoles.includes(newRole)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid role',
        validRoles
      });
    }
    
    const userToPromote = await BorisUser.findById(userId);
    if (!userToPromote) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Prevent self-demotion
    if (userId === req.userId && newRole !== 'super_admin') {
      return res.status(400).json({
        success: false,
        message: 'Cannot demote yourself'
      });
    }
    
    // Use the promoteToRole method from schema if it exists
    if (userToPromote.promoteToRole) {
      await userToPromote.promoteToRole(newRole, req.userId);
    } else {
      userToPromote.role = newRole;
      await userToPromote.save();
    }
    
    // If promoting to reseller, set discount
    if (newRole === 'reseller' && resellerDiscount) {
      userToPromote.business.resellerDiscount = resellerDiscount;
      userToPromote.business.type = 'reseller';
      await userToPromote.save();
    }
    
    res.json({
      success: true,
      message: `User promoted to ${newRole} successfully`,
      data: {
        userId: userToPromote._id,
        name: `${userToPromote.firstName} ${userToPromote.secondName}`,
        email: userToPromote.email,
        newRole,
        permissions: userToPromote.permissions
      }
    });
  })
);

// ============================================
// GET USER PERMISSIONS
// ============================================
router.get('/permissions',
  authenticate,
  asyncHandler(async (req, res) => {
    const user = await BorisUser.findById(req.userId).select('role permissions');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      data: {
        role: user.role,
        permissions: user.permissions,
        isAdmin: user.isAdmin ? user.isAdmin() : false,
        isSuperAdmin: user.isSuperAdmin ? user.isSuperAdmin() : false
      }
    });
  })
);

module.exports = router;