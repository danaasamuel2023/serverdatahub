// user.routes.js - User profile and account management routes (FIXED)
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

// Import models from schemas
const { BorisUser, OrderBoris } = require('../../schema/schema');

// Import middleware
const { authenticate, asyncHandler, rateLimit } = require('../../middleware/middleware');

// Apply authentication to all user routes
router.use(authenticate);

// ============================================
// GET USER PROFILE
// ============================================
router.get('/profile',
  asyncHandler(async (req, res) => {
    const userId = req.userId; // From authenticate middleware
    
    const user = await BorisUser.findById(userId)
      .select('-password -resetPasswordOTP -resetPasswordOTPExpiry');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Get user statistics - FIXED: Added 'new' keyword
    const [totalOrders, completedOrders, totalSpent] = await Promise.all([
      OrderBoris.countDocuments({ user: userId }),
      OrderBoris.countDocuments({ user: userId, status: 'completed' }),
      OrderBoris.aggregate([
        { $match: { user: new mongoose.Types.ObjectId(userId) } }, // FIXED
        { $group: { _id: null, total: { $sum: '$price' } } }
      ])
    ]);
    
    res.json({
      success: true,
      data: {
        profile: {
          id: user._id,
          firstName: user.firstName,
          secondName: user.secondName,
          email: user.email,
          phoneNumber: user.phoneNumber,
          business: user.business,
          role: user.role,
          isDisabled: user.isDisabled,
          createdAt: user.createdAt,
          lastPasswordReset: user.lastPasswordReset
        },
        wallet: {
          balance: user.wallet.balance,
          currency: user.wallet.currency,
          totalTransactions: user.wallet.transactions.length
        },
        statistics: {
          totalOrders,
          completedOrders,
          totalSpent: totalSpent[0]?.total || 0
        }
      }
    });
  })
);

// ============================================
// UPDATE USER PROFILE
// ============================================
router.put('/profile',
  rateLimit({ max: 10, windowMs: 60000 }), // 10 updates per minute
  asyncHandler(async (req, res) => {
    const userId = req.userId;
    const { 
      firstName, 
      secondName, 
      phoneNumber, 
      business 
    } = req.body;
    
    // Get current user
    const user = await BorisUser.findById(userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Check if disabled
    if (user.isDisabled) {
      return res.status(403).json({
        success: false,
        message: 'Account is disabled. Contact support.',
        disableReason: user.disableReason
      });
    }
    
    // Update allowed fields only
    const updates = {};
    
    if (firstName && firstName !== user.firstName) {
      if (firstName.length < 2) {
        return res.status(400).json({
          success: false,
          message: 'First name must be at least 2 characters long'
        });
      }
      updates.firstName = firstName;
    }
    
    if (secondName && secondName !== user.secondName) {
      if (secondName.length < 2) {
        return res.status(400).json({
          success: false,
          message: 'Second name must be at least 2 characters long'
        });
      }
      updates.secondName = secondName;
    }
    
    if (phoneNumber && phoneNumber !== user.phoneNumber) {
      // Validate phone number
      const phoneRegex = /^(?:\+233|233|0)(20|23|24|25|26|27|28|29|30|31|32|50|53|54|55|56|57|58|59)\d{7}$/;
      if (!phoneRegex.test(phoneNumber)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid Ghana phone number format'
        });
      }
      
      // Format phone number
      let formattedPhone = phoneNumber.replace(/\D/g, '');
      if (formattedPhone.startsWith('0')) {
        formattedPhone = '233' + formattedPhone.substring(1);
      }
      if (!formattedPhone.startsWith('233')) {
        formattedPhone = '233' + formattedPhone;
      }
      formattedPhone = '+' + formattedPhone;
      
      // Check if phone number is already taken
      const phoneExists = await BorisUser.exists({ 
        phoneNumber: formattedPhone,
        _id: { $ne: userId }
      });
      
      if (phoneExists) {
        return res.status(409).json({
          success: false,
          message: 'Phone number already registered to another account'
        });
      }
      
      updates.phoneNumber = formattedPhone;
    }
    
    // Update business information
    if (business) {
      const businessUpdates = {};
      
      if (business.name && business.name !== user.business.name) {
        if (business.name.length < 1) {
          return res.status(400).json({
            success: false,
            message: 'Business name is required'
          });
        }
        businessUpdates['business.name'] = business.name;
      }
      
      if (business.registrationNumber !== undefined) {
        businessUpdates['business.registrationNumber'] = business.registrationNumber;
      }
      
      if (business.address !== undefined) {
        businessUpdates['business.address'] = business.address;
      }
      
      Object.assign(updates, businessUpdates);
    }
    
    // Check if there are any updates
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No changes detected'
      });
    }
    
    // Apply updates
    const updatedUser = await BorisUser.findByIdAndUpdate(
      userId,
      { $set: updates },
      { 
        new: true, 
        runValidators: true,
        select: '-password -resetPasswordOTP -resetPasswordOTPExpiry -wallet.transactions'
      }
    );
    
    res.json({
      success: true,
      message: 'Profile updated successfully',
      data: {
        profile: {
          id: updatedUser._id,
          firstName: updatedUser.firstName,
          secondName: updatedUser.secondName,
          email: updatedUser.email,
          phoneNumber: updatedUser.phoneNumber,
          business: updatedUser.business
        }
      }
    });
  })
);

// ============================================
// UPDATE EMAIL (Requires password verification)
// ============================================
router.put('/profile/email',
  rateLimit({ max: 3, windowMs: 60000 }), // 3 attempts per minute
  asyncHandler(async (req, res) => {
    const userId = req.userId;
    const { newEmail, password } = req.body;
    
    // Validate input
    if (!newEmail || !password) {
      return res.status(400).json({
        success: false,
        message: 'New email and current password are required'
      });
    }
    
    // Validate email format
    const emailRegex = /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/;
    if (!emailRegex.test(newEmail)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }
    
    // Get user with password
    const user = await BorisUser.findById(userId).select('+password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid password'
      });
    }
    
    // Check if email is already taken
    const emailExists = await BorisUser.exists({ 
      email: newEmail.toLowerCase(),
      _id: { $ne: userId }
    });
    
    if (emailExists) {
      return res.status(409).json({
        success: false,
        message: 'Email already registered to another account'
      });
    }
    
    // Update email
    user.email = newEmail.toLowerCase();
    await user.save();
    
    res.json({
      success: true,
      message: 'Email updated successfully',
      data: {
        email: user.email
      }
    });
  })
);

// ============================================
// CHANGE PASSWORD (While logged in)
// ============================================
router.put('/profile/password',
  rateLimit({ max: 3, windowMs: 60000 }), // 3 attempts per minute
  asyncHandler(async (req, res) => {
    const userId = req.userId;
    const { currentPassword, newPassword } = req.body;
    
    // Validate input
    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Current password and new password are required'
      });
    }
    
    // Validate new password strength
    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'New password must be at least 6 characters long'
      });
    }
    
    // Don't allow same password
    if (currentPassword === newPassword) {
      return res.status(400).json({
        success: false,
        message: 'New password must be different from current password'
      });
    }
    
    // Get user with password
    const user = await BorisUser.findById(userId).select('+password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Verify current password
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }
    
    // Update password (will be hashed by pre-save hook)
    user.password = newPassword;
    user.lastPasswordReset = new Date();
    await user.save();
    
    res.json({
      success: true,
      message: 'Password changed successfully'
    });
  })
);

// ============================================
// GET WALLET INFORMATION
// ============================================
router.get('/wallet',
  asyncHandler(async (req, res) => {
    const userId = req.userId;
    
    const user = await BorisUser.findById(userId)
      .select('wallet firstName secondName email');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Calculate wallet statistics
    const transactions = user.wallet.transactions || [];
    const stats = transactions.reduce((acc, tx) => {
      if (tx.status === 'completed') {
        if (tx.type === 'credit') {
          acc.totalCredits += tx.amount;
          acc.creditCount++;
        } else {
          acc.totalDebits += tx.amount;
          acc.debitCount++;
        }
      }
      return acc;
    }, {
      totalCredits: 0,
      totalDebits: 0,
      creditCount: 0,
      debitCount: 0
    });
    
    // Get recent transactions (last 10)
    const recentTransactions = transactions
      .sort((a, b) => new Date(b.timestamp || b.createdAt) - new Date(a.timestamp || a.createdAt))
      .slice(0, 10)
      .map(tx => ({
        id: tx._id,
        type: tx.type,
        amount: tx.amount,
        description: tx.description,
        status: tx.status,
        timestamp: tx.timestamp || tx.createdAt,
        reference: tx.reference,
        balanceBefore: tx.balanceBefore,
        balanceAfter: tx.balanceAfter
      }));
    
    res.json({
      success: true,
      data: {
        balance: user.wallet.balance,
        currency: user.wallet.currency,
        statistics: {
          ...stats,
          totalTransactions: transactions.length,
          netFlow: stats.totalCredits - stats.totalDebits
        },
        recentTransactions
      }
    });
  })
);

// ============================================
// GET WALLET TRANSACTIONS
// ============================================
router.get('/wallet/transactions',
  asyncHandler(async (req, res) => {
    const userId = req.userId;
    const { page = 1, limit = 20, type, status, startDate, endDate } = req.query;
    
    const user = await BorisUser.findById(userId).select('wallet');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Filter transactions
    let transactions = user.wallet.transactions || [];
    
    if (type && ['credit', 'debit'].includes(type)) {
      transactions = transactions.filter(t => t.type === type);
    }
    
    if (status && ['pending', 'completed', 'failed'].includes(status)) {
      transactions = transactions.filter(t => t.status === status);
    }
    
    if (startDate || endDate) {
      const start = startDate ? new Date(startDate) : new Date(0);
      const end = endDate ? new Date(endDate) : new Date();
      end.setHours(23, 59, 59, 999);
      
      transactions = transactions.filter(t => {
        const txDate = new Date(t.timestamp || t.createdAt);
        return txDate >= start && txDate <= end;
      });
    }
    
    // Sort by newest first
    transactions.sort((a, b) => {
      const dateA = new Date(b.timestamp || b.createdAt);
      const dateB = new Date(a.timestamp || a.createdAt);
      return dateA - dateB;
    });
    
    // Paginate
    const startIndex = (parseInt(page) - 1) * parseInt(limit);
    const endIndex = startIndex + parseInt(limit);
    const paginatedTransactions = transactions.slice(startIndex, endIndex);
    
    res.json({
      success: true,
      data: {
        transactions: paginatedTransactions.map(tx => ({
          id: tx._id,
          type: tx.type,
          amount: tx.amount,
          description: tx.description,
          status: tx.status,
          timestamp: tx.timestamp || tx.createdAt,
          reference: tx.reference,
          paystackReference: tx.paystackReference,
          processingFee: tx.processingFee,
          balanceBefore: tx.balanceBefore,
          balanceAfter: tx.balanceAfter
        })),
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: transactions.length,
          pages: Math.ceil(transactions.length / limit)
        }
      }
    });
  })
);

// ============================================
// GET USER'S ORDERS
// ============================================
router.get('/orders',
  asyncHandler(async (req, res) => {
    const userId = req.userId;
    const { page = 1, limit = 20, status, networkKey, startDate, endDate } = req.query;
    
    // Build filter
    const filter = { user: userId };
    
    if (status) {
      filter.status = status;
    }
    
    if (networkKey) {
      filter.networkKey = networkKey;
    }
    
    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) {
        filter.createdAt.$gte = new Date(startDate);
      }
      if (endDate) {
        const end = new Date(endDate);
        end.setHours(23, 59, 59, 999);
        filter.createdAt.$lte = end;
      }
    }
    
    // Get orders
    const orders = await OrderBoris.find(filter)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit))
      .select('reference networkKey recipient capacity price status provider createdAt completedAt');
    
    const total = await OrderBoris.countDocuments(filter);
    
    res.json({
      success: true,
      data: {
        orders,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      }
    });
  })
);

// ============================================
// GET SINGLE ORDER DETAILS
// ============================================
router.get('/orders/:reference',
  asyncHandler(async (req, res) => {
    const userId = req.userId;
    const { reference } = req.params;
    
    const order = await OrderBoris.findOne({
      reference,
      user: userId
    });
    
    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }
    
    res.json({
      success: true,
      data: order
    });
  })
);

// ============================================
// DELETE ACCOUNT (Requires password)
// ============================================
router.delete('/account',
  rateLimit({ max: 3, windowMs: 3600000 }), // 3 attempts per hour
  asyncHandler(async (req, res) => {
    const userId = req.userId;
    const { password, confirmDelete } = req.body;
    
    // Validate input
    if (!password || !confirmDelete) {
      return res.status(400).json({
        success: false,
        message: 'Password and confirmation are required'
      });
    }
    
    if (confirmDelete !== 'DELETE MY ACCOUNT') {
      return res.status(400).json({
        success: false,
        message: 'Please type "DELETE MY ACCOUNT" to confirm'
      });
    }
    
    // Get user with password
    const user = await BorisUser.findById(userId).select('+password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Check if user has positive balance
    if (user.wallet.balance > 0) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete account with positive wallet balance. Please withdraw funds first.',
        currentBalance: user.wallet.balance
      });
    }
    
    // Check for pending orders
    const pendingOrders = await OrderBoris.countDocuments({
      user: userId,
      status: { $in: ['pending', 'processing', 'onPending'] }
    });
    
    if (pendingOrders > 0) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete account with pending orders',
        pendingOrders
      });
    }
    
    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid password'
      });
    }
    
    // Delete user
    await BorisUser.findByIdAndDelete(userId);
    
    res.json({
      success: true,
      message: 'Account deleted successfully'
    });
  })
);

module.exports = router;