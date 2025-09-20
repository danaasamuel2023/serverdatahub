// admin.routes.js - Admin management routes (FIXED)
const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');

// Import models from schemas
const { 
  BorisUser, 
  OrderBoris, 
  NetworkConfig, 
  SystemSettings,
  Admin 
} = require('../../schema/schema');

// Import middleware
const {
  loadSystemSettings,
  adminAuth,
  requireRole,
  asyncHandler,
  errorHandler
} = require('../../middleware/middleware');

// Apply middleware to all admin routes
router.use(loadSystemSettings);
router.use(adminAuth); // Require admin authentication

// ============================================
// DASHBOARD STATISTICS (UPDATED)
// ============================================
router.get('/dashboard',
  asyncHandler(async (req, res) => {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const thisMonth = new Date();
    thisMonth.setDate(1);
    thisMonth.setHours(0, 0, 0, 0);

    // Get statistics including provider breakdown
    const [
      totalUsers,
      activeUsers,
      todayOrders,
      monthOrders,
      pendingOrders,
      manualOrders,
      todayRevenue,
      monthRevenue,
      providerStats
    ] = await Promise.all([
      BorisUser.countDocuments(),
      BorisUser.countDocuments({ isDisabled: false }),
      OrderBoris.countDocuments({ createdAt: { $gte: today } }),
      OrderBoris.countDocuments({ createdAt: { $gte: thisMonth } }),
      OrderBoris.countDocuments({ status: 'pending' }),
      OrderBoris.countDocuments({ status: 'onPending' }), // Manual orders
      OrderBoris.aggregate([
        { $match: { createdAt: { $gte: today }, status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$price' } } }
      ]),
      OrderBoris.aggregate([
        { $match: { createdAt: { $gte: thisMonth }, status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$price' }, profit: { $sum: '$profit' } } }
      ]),
      OrderBoris.aggregate([
        { $match: { createdAt: { $gte: thisMonth } } },
        { $group: {
          _id: '$provider',
          count: { $sum: 1 },
          revenue: { $sum: '$price' },
          completed: {
            $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
          },
          failed: {
            $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
          }
        }}
      ])
    ]);

    res.json({
      success: true,
      data: {
        users: {
          total: totalUsers,
          active: activeUsers
        },
        orders: {
          today: todayOrders,
          thisMonth: monthOrders,
          pending: pendingOrders,
          manualPending: manualOrders
        },
        revenue: {
          today: todayRevenue[0]?.total || 0,
          thisMonth: monthRevenue[0]?.total || 0,
          monthProfit: monthRevenue[0]?.profit || 0
        },
        providers: providerStats
      }
    });
  })
);

// ============================================
// SYSTEM SETTINGS MANAGEMENT (UPDATED)
// ============================================
router.get('/settings',
  requireRole(['super_admin']),
  asyncHandler(async (req, res) => {
    let settings = await SystemSettings.findOne({ settingKey: 'MAIN_SETTINGS' })
      .select('+payment.paystack.secretKey +payment.paystack.webhookSecret +providers.geonectech.apiKey +providers.telecel.apiKey +providers.fgamail.apiKey');
    
    // Create default settings if not found
    if (!settings) {
      settings = await SystemSettings.create({
        settingKey: 'MAIN_SETTINGS',
        payment: {
          paystack: {
            publicKey: '',
            secretKey: '',
            testMode: true
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
            apiKey: '',
            baseUrl: 'https://testhub.geonettech.site/api/v1'
          },
          telecel: {
            enabled: true,
            apiKey: '8ef44b516735ec9455c4647ae980b445b3bc0be06e5a6095088eaa9cfbeb117e',
            baseUrl: 'https://iget.onrender.com/api/developer'
          },
          fgamail: {
            enabled: true,
            apiKey: '806fc6649c0a9597925dd0339c9b3cd6f7994ba3',
            baseUrl: 'https://fgamall.com/api/v1'
          },
          manual: {
            enabled: true
          }
        }
      });
    }
    
    res.json({
      success: true,
      data: settings
    });
  })
);

router.put('/settings',
  requireRole(['super_admin']),
  asyncHandler(async (req, res) => {
    const updates = req.body;
    
    const settings = await SystemSettings.findOneAndUpdate(
      { settingKey: 'MAIN_SETTINGS' },
      { $set: updates },
      { new: true, runValidators: true, upsert: true }
    );
    
    res.json({
      success: true,
      message: 'Settings updated successfully',
      data: settings
    });
  })
);

// Update specific provider settings
router.patch('/settings/provider/:provider',
  requireRole(['super_admin']),
  asyncHandler(async (req, res) => {
    const { provider } = req.params;
    const updates = req.body;
    
    const validProviders = ['geonectech', 'telecel', 'fgamail', 'manual'];
    if (!validProviders.includes(provider)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid provider'
      });
    }
    
    const updatePath = `providers.${provider}`;
    const updateObj = {};
    
    // Build update object dynamically
    Object.keys(updates).forEach(key => {
      updateObj[`${updatePath}.${key}`] = updates[key];
    });
    
    const settings = await SystemSettings.findOneAndUpdate(
      { settingKey: 'MAIN_SETTINGS' },
      { $set: updateObj },
      { new: true }
    );
    
    res.json({
      success: true,
      message: `${provider} settings updated successfully`,
      data: settings.providers[provider]
    });
  })
);

// ============================================
// USER MANAGEMENT
// ============================================
router.get('/users',
  asyncHandler(async (req, res) => {
    const { page = 1, limit = 50, search, status } = req.query;
    
    const filter = {};
    
    if (search) {
      filter.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { secondName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { phoneNumber: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (status === 'disabled') {
      filter.isDisabled = true;
    } else if (status === 'active') {
      filter.isDisabled = false;
    }
    
    const users = await BorisUser.find(filter)
      .select('-password -wallet.transactions')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));
    
    const total = await BorisUser.countDocuments(filter);
    
    res.json({
      success: true,
      data: {
        users,
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

// Manually adjust user wallet balance
router.post('/users/:userId/wallet/adjust',
  requireRole(['super_admin']),
  asyncHandler(async (req, res) => {
    const { userId } = req.params;
    const { amount, type, description, reason } = req.body;
    
    // Validate input
    if (!amount || !type || !description || !reason) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields',
        required: ['amount', 'type', 'description', 'reason']
      });
    }
    
    if (!['credit', 'debit'].includes(type)) {
      return res.status(400).json({
        success: false,
        message: 'Type must be either credit or debit'
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Amount must be positive'
      });
    }
    
    const user = await BorisUser.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Check if debit would make balance negative
    if (type === 'debit' && user.wallet.balance < amount) {
      return res.status(400).json({
        success: false,
        message: 'Insufficient balance for debit',
        currentBalance: user.wallet.balance,
        requestedDebit: amount
      });
    }
    
    const balanceBefore = user.wallet.balance;
    const balanceAfter = type === 'credit' 
      ? balanceBefore + amount 
      : balanceBefore - amount;
    
    // Create transaction record
    const transaction = {
      type,
      amount,
      description: `Admin adjustment: ${description}`,
      reference: `ADMIN-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      status: 'completed',
      completedAt: new Date(),
      timestamp: new Date(),
      balanceBefore,
      balanceAfter,
      processedBy: 'admin',
      apiResponse: {
        adjustedBy: req.adminId,
        reason,
        originalDescription: description
      }
    };
    
    // Update user wallet
    user.wallet.balance = balanceAfter;
    user.wallet.transactions.push(transaction);
    user.markModified('wallet');
    
    await user.save();
    
    res.json({
      success: true,
      message: `Wallet ${type} successful`,
      data: {
        userId: user._id,
        type,
        amount,
        balanceBefore,
        balanceAfter,
        transaction: transaction.reference
      }
    });
  })
);

// Disable/Enable user
router.patch('/users/:userId/status',
  requireRole(['super_admin', 'admin']),
  asyncHandler(async (req, res) => {
    const { userId } = req.params;
    const { isDisabled, reason } = req.body;
    
    const user = await BorisUser.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    if (isDisabled) {
      await user.disable(reason, req.adminId);
    } else {
      await user.enable();
    }
    
    res.json({
      success: true,
      message: `User ${isDisabled ? 'disabled' : 'enabled'} successfully`
    });
  })
);

// Get specific user details with wallet info
router.get('/users/:userId',
  asyncHandler(async (req, res) => {
    const { userId } = req.params;
    
    const user = await BorisUser.findById(userId)
      .select('-password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Get user statistics - FIXED: Use 'new' with ObjectId
    const [totalOrders, completedOrders, totalSpent] = await Promise.all([
      OrderBoris.countDocuments({ user: userId }),
      OrderBoris.countDocuments({ user: userId, status: 'completed' }),
      OrderBoris.aggregate([
        { $match: { user: new mongoose.Types.ObjectId(userId) } },  // FIXED
        { $group: { _id: null, total: { $sum: '$price' } } }
      ])
    ]);
    
    res.json({
      success: true,
      data: {
        user,
        statistics: {
          totalOrders,
          completedOrders,
          totalSpent: totalSpent[0]?.total || 0,
          walletBalance: user.wallet.balance,
          totalTransactions: user.wallet.transactions.length
        }
      }
    });
  })
);

// Get user's orders
router.get('/users/:userId/orders',
  asyncHandler(async (req, res) => {
    const { userId } = req.params;
    const { page = 1, limit = 50, status, startDate, endDate } = req.query;
    
    // Check if user exists
    const userExists = await BorisUser.exists({ _id: userId });
    if (!userExists) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Build filter
    const filter = { user: userId };
    
    if (status) {
      filter.status = status;
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
      .select('reference networkKey recipient capacity price status provider createdAt completedAt balanceBefore balanceAfter');
    
    const total = await OrderBoris.countDocuments(filter);
    
    // Get summary - FIXED: Use 'new' with ObjectId
    const summary = await OrderBoris.aggregate([
      { $match: { user: new mongoose.Types.ObjectId(userId) } },  // FIXED
      {
        $group: {
          _id: null,
          totalSpent: { $sum: '$price' },
          totalProfit: { $sum: '$profit' },
          avgOrderValue: { $avg: '$price' },
          completedCount: {
            $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
          },
          failedCount: {
            $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
          },
          pendingCount: {
            $sum: { $cond: [{ $eq: ['$status', 'onPending'] }, 1, 0] }
          }
        }
      }
    ]);
    
    res.json({
      success: true,
      data: {
        orders,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        },
        summary: summary[0] || {
          totalSpent: 0,
          totalProfit: 0,
          avgOrderValue: 0,
          completedCount: 0,
          failedCount: 0,
          pendingCount: 0
        }
      }
    });
  })
);

// Get user's wallet transactions
router.get('/users/:userId/transactions',
  asyncHandler(async (req, res) => {
    const { userId } = req.params;
    const { page = 1, limit = 50, type, status, startDate, endDate } = req.query;
    
    // Get user with transactions
    const user = await BorisUser.findById(userId)
      .select('wallet firstName secondName email');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Filter transactions
    let transactions = user.wallet.transactions || [];
    
    // Apply filters
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
    
    // Sort by timestamp (newest first)
    transactions.sort((a, b) => {
      const dateA = new Date(b.timestamp || b.createdAt);
      const dateB = new Date(a.timestamp || a.createdAt);
      return dateA - dateB;
    });
    
    // Calculate totals
    const totals = transactions.reduce((acc, tx) => {
      if (tx.type === 'credit') {
        acc.totalCredits += tx.amount;
        if (tx.status === 'completed') acc.completedCredits += tx.amount;
      } else {
        acc.totalDebits += tx.amount;
        if (tx.status === 'completed') acc.completedDebits += tx.amount;
      }
      return acc;
    }, {
      totalCredits: 0,
      totalDebits: 0,
      completedCredits: 0,
      completedDebits: 0
    });
    
    // Paginate
    const startIndex = (parseInt(page) - 1) * parseInt(limit);
    const endIndex = startIndex + parseInt(limit);
    const paginatedTransactions = transactions.slice(startIndex, endIndex);
    
    res.json({
      success: true,
      data: {
        user: {
          id: user._id,
          name: `${user.firstName} ${user.secondName}`,
          email: user.email,
          currentBalance: user.wallet.balance,
          currency: user.wallet.currency
        },
        transactions: paginatedTransactions,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: transactions.length,
          pages: Math.ceil(transactions.length / limit)
        },
        summary: {
          ...totals,
          netFlow: totals.completedCredits - totals.completedDebits,
          currentBalance: user.wallet.balance
        }
      }
    });
  })
);

// Get single transaction details
router.get('/users/:userId/transactions/:transactionRef',
  asyncHandler(async (req, res) => {
    const { userId, transactionRef } = req.params;
    
    // Get user
    const user = await BorisUser.findById(userId)
      .select('wallet firstName secondName email');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Find transaction
    const transaction = user.wallet.transactions.find(
      t => t.reference === transactionRef || 
          t.paystackReference === transactionRef ||
          t._id.toString() === transactionRef
    );
    
    if (!transaction) {
      return res.status(404).json({
        success: false,
        message: 'Transaction not found'
      });
    }
    
    // If it's a debit transaction, try to find the related order
    let relatedOrder = null;
    if (transaction.type === 'debit') {
      relatedOrder = await OrderBoris.findOne({
        $or: [
          { transactionReference: transaction.reference },
          { reference: transaction.reference }
        ]
      }).select('reference networkKey recipient capacity status createdAt completedAt');
    }
    
    res.json({
      success: true,
      data: {
        transaction,
        relatedOrder,
        user: {
          id: user._id,
          name: `${user.firstName} ${user.secondName}`,
          email: user.email
        }
      }
    });
  })
);

// Delete user
router.delete('/users/:userId',
  requireRole(['super_admin']),
  asyncHandler(async (req, res) => {
    const { userId } = req.params;
    
    const user = await BorisUser.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    if (user.wallet.balance > 0) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete user with positive balance'
      });
    }
    
    await BorisUser.findByIdAndDelete(userId);
    
    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  })
);

// ============================================
// ORDER MANAGEMENT (UPDATED)
// ============================================
router.get('/orders',
  asyncHandler(async (req, res) => {
    const { 
      page = 1, 
      limit = 50, 
      status, 
      networkKey,
      provider,
      startDate, 
      endDate,
      search 
    } = req.query;
    
    const filter = {};
    
    if (status) filter.status = status;
    if (networkKey) filter.networkKey = networkKey;
    if (provider) filter.provider = provider;
    
    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) {
        const end = new Date(endDate);
        end.setHours(23, 59, 59, 999);
        filter.createdAt.$lte = end;
      }
    }
    
    let orders;
    let total;
    
    if (search) {
      // Search in orders and join with users
      const aggregatePipeline = [
        {
          $lookup: {
            from: 'borisusers',
            localField: 'user',
            foreignField: '_id',
            as: 'userInfo'
          }
        },
        {
          $match: {
            ...filter,
            $or: [
              { reference: { $regex: search, $options: 'i' } },
              { recipient: { $regex: search, $options: 'i' } },
              { 'userInfo.firstName': { $regex: search, $options: 'i' } },
              { 'userInfo.email': { $regex: search, $options: 'i' } }
            ]
          }
        },
        { $sort: { createdAt: -1 } },
        { $skip: (parseInt(page) - 1) * parseInt(limit) },
        { $limit: parseInt(limit) }
      ];
      
      orders = await OrderBoris.aggregate(aggregatePipeline);
      
      // Count total
      const countPipeline = aggregatePipeline.slice(0, 2);
      countPipeline.push({ $count: 'total' });
      const countResult = await OrderBoris.aggregate(countPipeline);
      total = countResult[0]?.total || 0;
    } else {
      orders = await OrderBoris.find(filter)
        .populate('user', 'firstName secondName email phoneNumber wallet.balance')
        .sort({ createdAt: -1 })
        .limit(parseInt(limit))
        .skip((parseInt(page) - 1) * parseInt(limit));
      
      total = await OrderBoris.countDocuments(filter);
    }
    
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

// Get manual pending orders
router.get('/orders/manual-pending',
  asyncHandler(async (req, res) => {
    const { page = 1, limit = 50, networkKey } = req.query;
    
    const filter = { status: 'onPending' };
    if (networkKey) filter.networkKey = networkKey;
    
    const orders = await OrderBoris.find(filter)
      .populate('user', 'firstName secondName email phoneNumber')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));
    
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

// Get single order details
router.get('/orders/:orderId',
  asyncHandler(async (req, res) => {
    const { orderId } = req.params;
    
    const order = await OrderBoris.findById(orderId)
      .populate('user', 'firstName secondName email phoneNumber business.name wallet.balance');
    
    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }
    
    // Find related transaction if exists
    let relatedTransaction = null;
    if (order.user && order.transactionReference) {
      const user = await BorisUser.findById(order.user._id)
        .select('wallet.transactions');
      
      if (user) {
        relatedTransaction = user.wallet.transactions.find(
          t => t.reference === order.transactionReference
        );
      }
    }
    
    res.json({
      success: true,
      data: {
        order,
        relatedTransaction
      }
    });
  })
);

// Update order status
router.patch('/orders/:orderId/status',
  requireRole(['super_admin', 'admin']),
  asyncHandler(async (req, res) => {
    const { orderId } = req.params;
    const { status } = req.body;
    
    const validStatuses = ['pending', 'processing', 'completed', 'failed', 'onPending'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status'
      });
    }
    
    const order = await OrderBoris.findById(orderId);
    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }
    
    const previousStatus = order.status;
    order.status = status;
    
    // Update completion timestamp if marking as completed
    if (status === 'completed' && previousStatus !== 'completed') {
      order.completedAt = new Date();
    }
    
    await order.save();
    
    res.json({
      success: true,
      message: `Order status updated from ${previousStatus} to ${status}`,
      data: order
    });
  })
);

// Process manual order
router.post('/orders/:orderId/process-manual',
  requireRole(['super_admin', 'admin']),
  asyncHandler(async (req, res) => {
    const { orderId } = req.params;
    const { notes, markCompleted = false } = req.body;
    
    const order = await OrderBoris.findById(orderId);
    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }
    
    if (order.status !== 'onPending') {
      return res.status(400).json({
        success: false,
        message: 'Order is not in manual pending status'
      });
    }
    
    // Update order
    order.status = markCompleted ? 'completed' : 'processing';
    if (notes) {
      order.apiResponse = {
        ...order.apiResponse,
        manualProcessingNotes: notes,
        processedBy: req.adminId,
        processedAt: new Date()
      };
    }
    
    if (markCompleted) {
      order.completedAt = new Date();
    }
    
    await order.save();
    
    res.json({
      success: true,
      message: `Order ${markCompleted ? 'completed' : 'marked as processing'}`,
      data: order
    });
  })
);

// ============================================
// NETWORK CONFIGURATION (UPDATED)
// ============================================
router.get('/networks',
  asyncHandler(async (req, res) => {
    const networks = await NetworkConfig.find({});
    
    res.json({
      success: true,
      data: networks
    });
  })
);

// Update network provider configuration
router.patch('/networks/:networkKey/provider',
  requireRole(['super_admin', 'admin']),
  asyncHandler(async (req, res) => {
    const { networkKey } = req.params;
    const { primary, fallback, availableProviders } = req.body;
    
    const network = await NetworkConfig.findOne({ networkKey });
    if (!network) {
      return res.status(404).json({
        success: false,
        message: 'Network not found'
      });
    }
    
    // Validate providers
    const validProviders = ['GEONECTECH', 'TELECEL', 'FGAMAIL', 'MANUAL'];
    if (primary && !validProviders.includes(primary)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid primary provider'
      });
    }
    
    if (fallback && fallback !== 'null' && !validProviders.includes(fallback)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid fallback provider'
      });
    }
    
    // Update provider configuration
    if (primary !== undefined) {
      network.provider.primary = primary;
    }
    
    if (fallback !== undefined) {
      network.provider.fallback = fallback === 'null' ? null : fallback;
    }
    
    if (availableProviders && Array.isArray(availableProviders)) {
      const invalidProviders = availableProviders.filter(p => !validProviders.includes(p));
      if (invalidProviders.length > 0) {
        return res.status(400).json({
          success: false,
          message: `Invalid providers: ${invalidProviders.join(', ')}`
        });
      }
      network.provider.availableProviders = availableProviders;
    }
    
    network.markModified('provider');
    await network.save();
    
    res.json({
      success: true,
      message: 'Network provider configuration updated',
      data: network
    });
  })
);

// Update network prices
router.patch('/networks/:networkKey/prices',
  requireRole(['super_admin', 'admin']),
  asyncHandler(async (req, res) => {
    const { networkKey } = req.params;
    const { bundles } = req.body;
    
    const network = await NetworkConfig.findOne({ networkKey });
    if (!network) {
      return res.status(404).json({
        success: false,
        message: 'Network not found'
      });
    }
    
    // Update bundles
    bundles.forEach(update => {
      const bundle = network.bundles.find(b => b.capacity === update.capacity);
      if (bundle) {
        if (update.price !== undefined) bundle.price = update.price;
        if (update.resellerPrice !== undefined) bundle.resellerPrice = update.resellerPrice;
        if (update.isActive !== undefined) bundle.isActive = update.isActive;
      } else if (update.capacity && update.price && update.resellerPrice) {
        // Add new bundle
        network.bundles.push({
          capacity: update.capacity,
          price: update.price,
          resellerPrice: update.resellerPrice,
          isActive: update.isActive !== undefined ? update.isActive : true
        });
      }
    });
    
    // Sort bundles by capacity
    network.bundles.sort((a, b) => a.capacity - b.capacity);
    network.markModified('bundles');
    await network.save();
    
    res.json({
      success: true,
      message: 'Network prices updated successfully',
      data: network
    });
  })
);

// Toggle network status
router.patch('/networks/:networkKey/toggle',
  requireRole(['super_admin', 'admin']),
  asyncHandler(async (req, res) => {
    const { networkKey } = req.params;
    const { isActive } = req.body;
    
    const network = await NetworkConfig.findOneAndUpdate(
      { networkKey },
      { isActive },
      { new: true }
    );
    
    if (!network) {
      return res.status(404).json({
        success: false,
        message: 'Network not found'
      });
    }
    
    res.json({
      success: true,
      message: `Network ${isActive ? 'activated' : 'deactivated'}`,
      data: network
    });
  })
);

// ============================================
// FINANCIAL REPORTS (UPDATED)
// ============================================
router.get('/reports/daily',
  asyncHandler(async (req, res) => {
    const { date } = req.query;
    const targetDate = date ? new Date(date) : new Date();
    
    const startOfDay = new Date(targetDate);
    startOfDay.setHours(0, 0, 0, 0);
    const endOfDay = new Date(targetDate);
    endOfDay.setHours(23, 59, 59, 999);
    
    const [ordersByNetwork, ordersByProvider] = await Promise.all([
      OrderBoris.aggregate([
        {
          $match: {
            createdAt: { $gte: startOfDay, $lte: endOfDay }
          }
        },
        {
          $group: {
            _id: '$networkKey',
            count: { $sum: 1 },
            revenue: { $sum: '$price' },
            cost: { $sum: '$resellerPrice' },
            profit: { $sum: '$profit' },
            bundles: {
              $push: {
                capacity: '$capacity',
                price: '$price',
                profit: '$profit'
              }
            }
          }
        }
      ]),
      OrderBoris.aggregate([
        {
          $match: {
            createdAt: { $gte: startOfDay, $lte: endOfDay }
          }
        },
        {
          $group: {
            _id: '$provider',
            count: { $sum: 1 },
            revenue: { $sum: '$price' },
            completed: {
              $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
            },
            failed: {
              $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
            },
            pending: {
              $sum: { $cond: [{ $eq: ['$status', 'onPending'] }, 1, 0] }
            }
          }
        }
      ])
    ]);
    
    const summary = ordersByNetwork.reduce((acc, curr) => {
      acc.totalOrders += curr.count;
      acc.totalRevenue += curr.revenue;
      acc.totalCost += curr.cost;
      acc.totalProfit += curr.profit;
      return acc;
    }, {
      totalOrders: 0,
      totalRevenue: 0,
      totalCost: 0,
      totalProfit: 0
    });
    
    res.json({
      success: true,
      data: {
        date: startOfDay.toISOString().split('T')[0],
        summary,
        byNetwork: ordersByNetwork,
        byProvider: ordersByProvider
      }
    });
  })
);

router.get('/reports/monthly',
  asyncHandler(async (req, res) => {
    const { month, year } = req.query;
    const targetYear = year || new Date().getFullYear();
    const targetMonth = month || new Date().getMonth();
    
    const startOfMonth = new Date(targetYear, targetMonth, 1);
    const endOfMonth = new Date(targetYear, targetMonth + 1, 0, 23, 59, 59, 999);
    
    const [dailyStats, providerStats] = await Promise.all([
      OrderBoris.aggregate([
        {
          $match: {
            createdAt: { $gte: startOfMonth, $lte: endOfMonth }
          }
        },
        {
          $group: {
            _id: {
              day: { $dayOfMonth: '$createdAt' },
              status: '$status'
            },
            count: { $sum: 1 },
            revenue: { $sum: '$price' },
            profit: { $sum: '$profit' }
          }
        },
        {
          $sort: { '_id.day': 1 }
        }
      ]),
      OrderBoris.aggregate([
        {
          $match: {
            createdAt: { $gte: startOfMonth, $lte: endOfMonth }
          }
        },
        {
          $group: {
            _id: '$provider',
            count: { $sum: 1 },
            revenue: { $sum: '$price' },
            profit: { $sum: '$profit' },
            successRate: {
              $avg: { $cond: [{ $eq: ['$status', 'completed'] }, 100, 0] }
            }
          }
        }
      ])
    ]);
    
    res.json({
      success: true,
      data: {
        month: `${targetYear}-${String(targetMonth + 1).padStart(2, '0')}`,
        dailyStats,
        providerStats
      }
    });
  })
);

// Provider performance report
router.get('/reports/provider-performance',
  asyncHandler(async (req, res) => {
    const { days = 7 } = req.query;
    
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));
    startDate.setHours(0, 0, 0, 0);
    
    const performance = await OrderBoris.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate },
          provider: { $ne: null }
        }
      },
      {
        $group: {
          _id: {
            provider: '$provider',
            networkKey: '$networkKey'
          },
          totalOrders: { $sum: 1 },
          completedOrders: {
            $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
          },
          failedOrders: {
            $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
          },
          pendingOrders: {
            $sum: { $cond: [{ $eq: ['$status', 'onPending'] }, 1, 0] }
          },
          processingOrders: {
            $sum: { $cond: [{ $eq: ['$status', 'processing'] }, 1, 0] }
          },
          totalRevenue: { $sum: '$price' },
          avgProcessingTime: {
            $avg: {
              $cond: [
                { $ne: ['$completedAt', null] },
                { $subtract: ['$completedAt', '$createdAt'] },
                null
              ]
            }
          }
        }
      },
      {
        $group: {
          _id: '$_id.provider',
          networks: {
            $push: {
              network: '$_id.networkKey',
              totalOrders: '$totalOrders',
              completedOrders: '$completedOrders',
              failedOrders: '$failedOrders',
              pendingOrders: '$pendingOrders',
              processingOrders: '$processingOrders',
              revenue: '$totalRevenue',
              avgProcessingTime: '$avgProcessingTime'
            }
          },
          totalOrders: { $sum: '$totalOrders' },
          completedOrders: { $sum: '$completedOrders' },
          failedOrders: { $sum: '$failedOrders' },
          pendingOrders: { $sum: '$pendingOrders' },
          totalRevenue: { $sum: '$totalRevenue' },
          successRate: {
            $avg: {
              $multiply: [
                { $divide: ['$completedOrders', '$totalOrders'] },
                100
              ]
            }
          }
        }
      }
    ]);
    
    res.json({
      success: true,
      data: {
        period: `Last ${days} days`,
        startDate,
        providers: performance
      }
    });
  })
);

// ============================================
// ADMIN MANAGEMENT
// ============================================
router.get('/admins',
  requireRole(['super_admin']),
  asyncHandler(async (req, res) => {
    const admins = await Admin.find({})
      .select('-password')
      .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      data: admins
    });
  })
);

router.post('/admins',
  requireRole(['super_admin']),
  asyncHandler(async (req, res) => {
    const { username, email, password, role } = req.body;
    
    const admin = await Admin.create({
      username,
      email,
      password,
      role
    });
    
    res.status(201).json({
      success: true,
      message: 'Admin created successfully',
      data: {
        id: admin._id,
        username: admin.username,
        email: admin.email,
        role: admin.role
      }
    });
  })
);

router.delete('/admins/:adminId',
  requireRole(['super_admin']),
  asyncHandler(async (req, res) => {
    const { adminId } = req.params;
    
    if (adminId === req.adminId) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete your own admin account'
      });
    }
    
    await Admin.findByIdAndDelete(adminId);
    
    res.json({
      success: true,
      message: 'Admin deleted successfully'
    });
  })
);

router.patch('/orders/bulk/status',
  requireRole(['super_admin', 'admin']),
  asyncHandler(async (req, res) => {
    const { orderIds, status } = req.body;
    
    // Validate input
    if (!orderIds || !Array.isArray(orderIds) || orderIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an array of order IDs'
      });
    }
    
    const validStatuses = ['pending', 'processing', 'completed', 'failed', 'onPending'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status'
      });
    }
    
    // Process bulk update
    const results = {
      successful: [],
      failed: [],
      notFound: []
    };
    
    // Process updates in batches
    for (const orderId of orderIds) {
      try {
        const order = await OrderBoris.findById(orderId);
        
        if (!order) {
          results.notFound.push(orderId);
          continue;
        }
        
        const previousStatus = order.status;
        order.status = status;
        
        // Update completion timestamp if marking as completed
        if (status === 'completed' && previousStatus !== 'completed') {
          order.completedAt = new Date();
        }
        
        await order.save();
        results.successful.push({
          orderId: order._id,
          reference: order.reference,
          previousStatus,
          newStatus: status
        });
        
      } catch (error) {
        results.failed.push({
          orderId,
          error: error.message
        });
      }
    }
    
    res.json({
      success: true,
      message: `Bulk status update completed`,
      data: {
        totalProcessed: orderIds.length,
        successful: results.successful.length,
        failed: results.failed.length,
        notFound: results.notFound.length,
        results
      }
    });
  })
);

// Get all transactions across all users
router.get('/transactions',
  asyncHandler(async (req, res) => {
    const { page = 1, limit = 50, type, status, startDate, endDate, userId } = req.query;
    
    // Build user filter
    const userFilter = userId ? { _id: userId } : {};
    
    // Get all users with their transactions
    const users = await BorisUser.find(userFilter)
      .select('wallet.transactions firstName secondName email phoneNumber business.name')
      .sort({ createdAt: -1 });
    
    // Aggregate all transactions with user info
    let allTransactions = [];
    users.forEach(user => {
      if (user.wallet?.transactions && user.wallet.transactions.length > 0) {
        user.wallet.transactions.forEach(tx => {
          allTransactions.push({
            ...tx.toObject(),
            user: {
              _id: user._id,
              firstName: user.firstName,
              secondName: user.secondName,
              email: user.email,
              phoneNumber: user.phoneNumber,
              businessName: user.business?.name
            }
          });
        });
      }
    });
    
    // Apply filters
    if (type && ['credit', 'debit'].includes(type)) {
      allTransactions = allTransactions.filter(t => t.type === type);
    }
    
    if (status && ['pending', 'completed', 'failed'].includes(status)) {
      allTransactions = allTransactions.filter(t => t.status === status);
    }
    
    if (startDate || endDate) {
      const start = startDate ? new Date(startDate) : new Date(0);
      const end = endDate ? new Date(endDate) : new Date();
      end.setHours(23, 59, 59, 999);
      
      allTransactions = allTransactions.filter(t => {
        const txDate = new Date(t.timestamp || t.createdAt);
        return txDate >= start && txDate <= end;
      });
    }
    
    // Sort by date (newest first)
    allTransactions.sort((a, b) => {
      const dateA = new Date(b.timestamp || b.createdAt);
      const dateB = new Date(a.timestamp || a.createdAt);
      return dateA - dateB;
    });
    
    // Calculate summary
    const summary = allTransactions.reduce((acc, tx) => {
      if (tx.type === 'credit') {
        acc.totalCredits += tx.amount || 0;
        if (tx.status === 'completed') acc.completedCredits += tx.amount || 0;
      } else if (tx.type === 'debit') {
        acc.totalDebits += tx.amount || 0;
        if (tx.status === 'completed') acc.completedDebits += tx.amount || 0;
      }
      return acc;
    }, {
      totalCredits: 0,
      totalDebits: 0,
      completedCredits: 0,
      completedDebits: 0
    });
    
    summary.netFlow = summary.completedCredits - summary.completedDebits;
    
    // Get total system balance
    const systemBalance = users.reduce((sum, user) => sum + (user.wallet?.balance || 0), 0);
    summary.systemBalance = systemBalance;
    
    // Paginate
    const startIndex = (parseInt(page) - 1) * parseInt(limit);
    const endIndex = startIndex + parseInt(limit);
    const paginatedTransactions = allTransactions.slice(startIndex, endIndex);
    
    res.json({
      success: true,
      data: {
        transactions: paginatedTransactions,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: allTransactions.length,
          pages: Math.ceil(allTransactions.length / limit)
        },
        summary: summary,
        totalUsers: users.length
      }
    });
  })
);

// Get transaction statistics
router.get('/transactions/stats',
  asyncHandler(async (req, res) => {
    const { startDate, endDate } = req.query;
    
    // Date filter
    const dateFilter = {};
    if (startDate || endDate) {
      const start = startDate ? new Date(startDate) : new Date(0);
      const end = endDate ? new Date(endDate) : new Date();
      end.setHours(23, 59, 59, 999);
      
      dateFilter.createdAt = { $gte: start, $lte: end };
    }
    
    // Get all users with transactions
    const users = await BorisUser.find({})
      .select('wallet.transactions');
    
    // Calculate statistics
    let stats = {
      totalTransactions: 0,
      totalCredits: 0,
      totalDebits: 0,
      completedTransactions: 0,
      pendingTransactions: 0,
      failedTransactions: 0,
      averageTransactionAmount: 0,
      largestTransaction: 0,
      transactionsByChannel: {},
      transactionsByType: { credit: 0, debit: 0 },
      transactionsByStatus: { pending: 0, completed: 0, failed: 0 }
    };
    
    let allTransactions = [];
    users.forEach(user => {
      if (user.wallet?.transactions) {
        user.wallet.transactions.forEach(tx => {
          // Apply date filter if provided
          const txDate = new Date(tx.timestamp || tx.createdAt);
          if (dateFilter.createdAt) {
            if (txDate < dateFilter.createdAt.$gte || txDate > dateFilter.createdAt.$lte) {
              return;
            }
          }
          
          allTransactions.push(tx);
          stats.totalTransactions++;
          
          // Type statistics
          if (tx.type === 'credit') {
            stats.totalCredits += tx.amount || 0;
            stats.transactionsByType.credit++;
          } else if (tx.type === 'debit') {
            stats.totalDebits += tx.amount || 0;
            stats.transactionsByType.debit++;
          }
          
          // Status statistics
          if (tx.status === 'completed') {
            stats.completedTransactions++;
            stats.transactionsByStatus.completed++;
          } else if (tx.status === 'pending') {
            stats.pendingTransactions++;
            stats.transactionsByStatus.pending++;
          } else if (tx.status === 'failed') {
            stats.failedTransactions++;
            stats.transactionsByStatus.failed++;
          }
          
          // Channel statistics
          if (tx.channel) {
            stats.transactionsByChannel[tx.channel] = (stats.transactionsByChannel[tx.channel] || 0) + 1;
          }
          
          // Largest transaction
          if (tx.amount > stats.largestTransaction) {
            stats.largestTransaction = tx.amount;
          }
        });
      }
    });
    
    // Calculate average
    if (stats.totalTransactions > 0) {
      const totalAmount = stats.totalCredits + stats.totalDebits;
      stats.averageTransactionAmount = totalAmount / stats.totalTransactions;
    }
    
    // Calculate daily average
    if (dateFilter.createdAt) {
      const daysDiff = Math.ceil((dateFilter.createdAt.$lte - dateFilter.createdAt.$gte) / (1000 * 60 * 60 * 24));
      stats.dailyAverage = {
        transactions: stats.totalTransactions / daysDiff,
        credits: stats.totalCredits / daysDiff,
        debits: stats.totalDebits / daysDiff
      };
    }
    
    res.json({
      success: true,
      data: stats
    });
  })
);

// Export transactions to CSV
router.get('/transactions/export',
  requireRole(['super_admin', 'admin']),
  asyncHandler(async (req, res) => {
    const { startDate, endDate, type, status } = req.query;
    
    // Get all users with transactions
    const users = await BorisUser.find({})
      .select('wallet.transactions firstName secondName email');
    
    // Aggregate and filter transactions
    let transactions = [];
    users.forEach(user => {
      if (user.wallet?.transactions) {
        user.wallet.transactions.forEach(tx => {
          // Apply filters
          if (type && tx.type !== type) return;
          if (status && tx.status !== status) return;
          
          if (startDate || endDate) {
            const txDate = new Date(tx.timestamp || tx.createdAt);
            const start = startDate ? new Date(startDate) : new Date(0);
            const end = endDate ? new Date(endDate) : new Date();
            end.setHours(23, 59, 59, 999);
            
            if (txDate < start || txDate > end) return;
          }
          
          transactions.push({
            reference: tx.reference || '',
            type: tx.type,
            amount: tx.amount,
            status: tx.status,
            description: tx.description || '',
            channel: tx.channel || '',
            processingFee: tx.processingFee || 0,
            balanceBefore: tx.balanceBefore || 0,
            balanceAfter: tx.balanceAfter || 0,
            userName: `${user.firstName} ${user.secondName}`,
            userEmail: user.email,
            date: new Date(tx.timestamp || tx.createdAt).toISOString()
          });
        });
      }
    });
    
    // Sort by date
    transactions.sort((a, b) => new Date(b.date) - new Date(a.date));
    
    // Convert to CSV
    const headers = [
      'Reference',
      'Type',
      'Amount',
      'Status',
      'Description',
      'Channel',
      'Processing Fee',
      'Balance Before',
      'Balance After',
      'User Name',
      'User Email',
      'Date'
    ];
    
    const csvContent = [
      headers.join(','),
      ...transactions.map(tx => [
        tx.reference,
        tx.type,
        tx.amount,
        tx.status,
        `"${tx.description}"`,
        tx.channel,
        tx.processingFee,
        tx.balanceBefore,
        tx.balanceAfter,
        `"${tx.userName}"`,
        tx.userEmail,
        tx.date
      ].join(','))
    ].join('\n');
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=transactions.csv');
    res.send(csvContent);
  })
);

// Apply error handler
router.use(errorHandler);

module.exports = router;