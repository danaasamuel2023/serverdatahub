// api.routes.js - API routes for developers
const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

// Import models from updated schemas
const { 
  BorisUser, 
  OrderBoris, 
  NetworkConfig, 
  SystemSettings 
} = require('../schema/schema');

// Import middleware
const { asyncHandler } = require('../middleware/middleware');

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key_change_in_production';
const API_TIMEOUT = 10000; // 10 seconds

// Rate limiter for purchase endpoint
const purchaseLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute window
  max: 5, // limit each user to 5 requests per window
  message: 'Too many order attempts, please try again after a minute',
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.developer?._id || req.ip
});

// Rate limiter for API key generation
const keyGenerationLimiter = rateLimit({
  windowMs: 3600 * 1000, // 1 hour window
  max: 3, // limit to 3 key generation attempts per hour
  message: 'Too many API key generation attempts'
});

// ============================================
// HELPER FUNCTIONS
// ============================================

// Generate order reference
function generateOrderReference() {
  const timestamp = Date.now().toString(36).toUpperCase();
  const random = Math.random().toString(36).substring(2, 8).toUpperCase();
  return `API${timestamp}${random}`;
}

// Generate idempotency key for orders
function generateIdempotencyKey(userId, recipient, capacity, networkKey) {
  return crypto.createHash('sha256')
    .update(`${userId}-${recipient}-${capacity}-${networkKey}-${Math.floor(Date.now() / 10000)}`)
    .digest('hex');
}

// Enhanced API Authentication middleware
const authenticateApiKey = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({ 
      status: 'error',
      message: 'API key is missing',
      code: 'MISSING_API_KEY'
    });
  }

  try {
    const decoded = jwt.verify(apiKey, JWT_SECRET);
    const user = await BorisUser.findById(decoded.userId)
      .select('-password -resetPasswordOTP -resetPasswordOTPExpiry');
    
    if (!user) {
      return res.status(401).json({ 
        status: 'error',
        message: 'Invalid API key - user not found',
        code: 'INVALID_API_KEY'
      });
    }
    
    if (user.isDisabled) {
      return res.status(403).json({
        status: 'error',
        message: 'Account is disabled',
        code: 'ACCOUNT_DISABLED',
        disableReason: user.disableReason
      });
    }
    
    req.developer = user;
    next();
  } catch (error) {
    console.error('API Authentication error:', error.message);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        status: 'error',
        message: 'API key has expired',
        code: 'API_KEY_EXPIRED'
      });
    }
    
    return res.status(401).json({ 
      status: 'error',
      message: 'Invalid API key',
      code: 'INVALID_API_KEY',
      error: error.message
    });
  }
};

// Process order with provider based on network configuration
async function processOrderWithProvider(networkConfig, networkKey, recipient, capacity, reference, settings) {
  const primaryProvider = networkConfig.provider?.primary || 'MANUAL';
  const fallbackProvider = networkConfig.provider?.fallback;
  
  console.log(`Processing order for ${networkKey} - Primary: ${primaryProvider}, Fallback: ${fallbackProvider}`);
  
  // Try primary provider first
  let result = await callProviderAPI(primaryProvider, networkKey, recipient, capacity, reference, settings);
  
  if (!result.success && fallbackProvider) {
    console.log(`Primary provider ${primaryProvider} failed, trying fallback ${fallbackProvider}`);
    result = await callProviderAPI(fallbackProvider, networkKey, recipient, capacity, reference, settings);
  }
  
  return result;
}

// Call specific provider API
async function callProviderAPI(provider, networkKey, recipient, capacity, reference, settings) {
  try {
    switch (provider) {
      case 'MANUAL':
        return {
          success: true,
          provider: 'MANUAL',
          isManual: true,
          status: 'onPending'
        };
        
      case 'GEONECTECH':
        if (!settings.providers.geonectech.enabled) {
          throw new Error('GeoNetTech provider is disabled');
        }
        
        const geonetPayload = { 
          network_key: networkKey, 
          ref: reference, 
          recipient, 
          capacity
        };
        
        const geonetResponse = await axios.post(
          `${settings.providers.geonectech.baseUrl}/placeOrder`,
          geonetPayload,
          { 
            headers: { 
              Authorization: `Bearer ${settings.providers.geonectech.apiKey}`,
              'Content-Type': 'application/json'
            },
            timeout: API_TIMEOUT
          }
        );
        
        return {
          success: true,
          provider: 'GEONECTECH',
          data: geonetResponse.data,
          orderId: geonetResponse.data.data?.orderId,
          status: 'processing'
        };
        
      case 'TELECEL':
        if (!settings.providers.telecel.enabled || networkKey !== 'TELECEL') {
          throw new Error('Telecel provider is not available for this network');
        }
        
        const telecelPayload = {
          recipientNumber: recipient,
          capacity: capacity,
          bundleType: "Telecel-5959",
          reference: reference
        };
        
        const telecelResponse = await axios.post(
          `${settings.providers.telecel.baseUrl}/orders/place`,
          telecelPayload,
          { 
            headers: { 
              'Content-Type': 'application/json',
              'X-API-Key': settings.providers.telecel.apiKey
            },
            timeout: API_TIMEOUT
          }
        );
        
        return {
          success: true,
          provider: 'TELECEL',
          data: telecelResponse.data,
          orderId: telecelResponse.data.data?.order?.id,
          apiOrderReference: telecelResponse.data.data?.order?.orderReference,
          status: 'processing'
        };
        
      case 'FGAMAIL':
        if (!settings.providers.fgamail.enabled || networkKey !== 'AT_PREMIUM') {
          throw new Error('FGAMAIL provider is not available for this network');
        }
        
        const formattedRecipient = recipient.startsWith('0') ? recipient : `0${recipient.slice(-9)}`;
        const capacityInMB = capacity * 1000;
        
        const fgamailPayload = {
          recipient_msisdn: formattedRecipient,
          shared_bundle: capacityInMB,
          order_reference: reference
        };
        
        const fgamailResponse = await axios.post(
          `${settings.providers.fgamail.baseUrl}/buy-ishare-package`,
          fgamailPayload,
          { 
            headers: { 
              'Content-Type': 'application/json',
              'Accept': 'application/json',
              'x-api-key': settings.providers.fgamail.apiKey
            },
            timeout: API_TIMEOUT
          }
        );
        
        return {
          success: true,
          provider: 'FGAMAIL',
          data: fgamailResponse.data,
          vendorTranxId: fgamailResponse.data.vendorTranxId,
          status: fgamailResponse.data.status || 'processing'
        };
        
      default:
        throw new Error(`Unknown provider: ${provider}`);
    }
  } catch (error) {
    console.error(`Provider ${provider} API error:`, error.message);
    return {
      success: false,
      provider,
      error: {
        message: error.message,
        details: error.response?.data
      }
    };
  }
}

// ============================================
// API KEY GENERATION
// ============================================
router.post('/generate-key', 
  keyGenerationLimiter,
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        status: 'error',
        message: 'Email and password are required',
        code: 'MISSING_CREDENTIALS'
      });
    }

    // Find user and verify password
    const user = await BorisUser.findOne({ email: email.toLowerCase() })
      .select('+password');
    
    if (!user) {
      return res.status(401).json({
        status: 'error',
        message: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    // Verify password using bcrypt
    const isValidPassword = await bcrypt.compare(password, user.password);
    
    if (!isValidPassword) {
      return res.status(401).json({
        status: 'error',
        message: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    // Check if account is disabled
    if (user.isDisabled) {
      return res.status(403).json({
        status: 'error',
        message: 'Account is disabled',
        code: 'ACCOUNT_DISABLED',
        disableReason: user.disableReason
      });
    }

    // Generate API key
    const apiKey = jwt.sign(
      { 
        userId: user._id,
        email: user.email,
        type: 'api'
      },
      JWT_SECRET,
      { expiresIn: '1y' }
    );

    res.json({
      status: 'success',
      data: {
        apiKey,
        expiresIn: '1 year',
        userId: user._id,
        email: user.email
      }
    });
  })
);

// ============================================
// WALLET ENDPOINTS
// ============================================
router.get('/wallet/balance', 
  authenticateApiKey, 
  asyncHandler(async (req, res) => {
    const user = await BorisUser.findById(req.developer._id);
    
    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }
    
    res.json({
      status: 'success',
      data: {
        balance: user.wallet.balance,
        currency: user.wallet.currency || 'GHS'
      }
    });
  })
);

// ============================================
// NETWORK INFORMATION
// ============================================
router.get('/networks', 
  authenticateApiKey,
  asyncHandler(async (req, res) => {
    const networks = await NetworkConfig.find({ isActive: true })
      .select('networkKey name bundles');
    
    const formattedNetworks = networks.map(network => ({
      networkKey: network.networkKey,
      name: network.name,
      bundles: network.bundles
        .filter(bundle => bundle.isActive)
        .map(bundle => ({
          capacity: bundle.capacity,
          price: bundle.price,
          unit: 'GB'
        }))
        .sort((a, b) => a.capacity - b.capacity)
    }));
    
    res.json({
      status: 'success',
      data: {
        networks: formattedNetworks
      }
    });
  })
);

// ============================================
// PURCHASE ENDPOINT
// ============================================
router.post('/purchase', 
  purchaseLimiter, 
  authenticateApiKey, 
  asyncHandler(async (req, res) => {
    const { networkKey, recipient, capacity } = req.body;
    const session = await mongoose.startSession();
    
    try {
      // Input validation
      if (!networkKey || !recipient || !capacity) {
        return res.status(400).json({
          status: 'error',
          message: 'Missing required fields',
          code: 'MISSING_REQUIRED_FIELDS',
          required: ['networkKey', 'recipient', 'capacity']
        });
      }

      // Validate phone number
      const phoneRegex = /^(?:\+233|233|0)(20|23|24|25|26|27|28|29|30|31|32|50|53|54|55|56|57|58|59)\d{7}$/;
      if (!phoneRegex.test(recipient)) {
        return res.status(400).json({
          status: 'error',
          message: 'Invalid Ghana phone number format',
          code: 'INVALID_PHONE_FORMAT'
        });
      }

      const numericCapacity = parseFloat(capacity);
      if (isNaN(numericCapacity) || numericCapacity <= 0) {
        return res.status(400).json({
          status: 'error',
          message: 'Invalid capacity value',
          code: 'INVALID_CAPACITY'
        });
      }

      // Check for duplicate order
      const recentDuplicateOrder = await OrderBoris.findOne({
        user: req.developer._id,
        recipient: recipient,
        capacity: numericCapacity,
        networkKey: networkKey,
        createdAt: { $gte: new Date(Date.now() - 5 * 60 * 1000) }, // Last 5 minutes
        status: { $nin: ['failed', 'cancelled'] }
      });

      if (recentDuplicateOrder) {
        return res.status(409).json({
          status: 'error',
          message: 'A similar order was recently placed',
          code: 'DUPLICATE_ORDER',
          data: {
            existingOrderId: recentDuplicateOrder._id,
            existingReference: recentDuplicateOrder.reference,
            status: recentDuplicateOrder.status
          }
        });
      }

      // Get system settings
      const settings = await SystemSettings.findOne({ settingKey: 'MAIN_SETTINGS' })
        .select('+providers.geonectech.apiKey +providers.telecel.apiKey +providers.fgamail.apiKey');
      
      if (!settings) {
        throw new Error('System not configured');
      }

      // Process order in transaction
      const result = await session.withTransaction(async () => {
        // Get user
        const user = await BorisUser.findById(req.developer._id).session(session);
        if (!user) {
          throw new Error('User not found');
        }

        // Get network configuration
        const network = await NetworkConfig.findOne({ 
          networkKey, 
          isActive: true 
        }).session(session);
        
        if (!network) {
          throw new Error(`Network ${networkKey} is not available`);
        }

        // Find bundle
        const bundle = network.bundles.find(b => 
          b.capacity === numericCapacity && b.isActive
        );
        
        if (!bundle) {
          const availableBundles = network.bundles
            .filter(b => b.isActive)
            .map(b => `${b.capacity}GB`)
            .join(', ');
          throw new Error(`${numericCapacity}GB bundle not available. Available: ${availableBundles}`);
        }

        const price = bundle.price;
        const resellerPrice = bundle.resellerPrice;
        const profit = price - resellerPrice;

        // Check wallet balance
        if (user.wallet.balance < price) {
          throw new Error(`Insufficient balance. Required: GHS ${price.toFixed(2)}, Available: GHS ${user.wallet.balance.toFixed(2)}`);
        }

        // Track balance changes
        const balanceBefore = user.wallet.balance;
        const balanceAfter = balanceBefore - price;

        // Generate reference
        const reference = generateOrderReference();
        const idempotencyKey = generateIdempotencyKey(req.developer._id, recipient, numericCapacity, networkKey);

        // Create order
        const order = new OrderBoris({
          user: req.developer._id,
          reference,
          transactionReference: new mongoose.Types.ObjectId().toString(),
          networkKey,
          recipient,
          capacity: numericCapacity,
          price,
          resellerPrice,
          profit,
          status: 'pending',
          balanceBefore,
          balanceAfter
        });

        await order.save({ session });

        // Debit wallet
        user.wallet.transactions.push({
          type: 'debit',
          amount: price,
          description: `API Order: ${networkKey} ${numericCapacity}GB for ${recipient}`,
          reference: order.transactionReference,
          timestamp: new Date(),
          status: 'completed',
          balanceBefore,
          balanceAfter
        });
        user.wallet.balance = balanceAfter;
        user.markModified('wallet');
        await user.save({ session });

        return {
          order,
          network,
          newBalance: balanceAfter,
          reference
        };
      });

      // Process with provider (outside transaction)
      const providerResult = await processOrderWithProvider(
        result.network,
        networkKey,
        recipient,
        numericCapacity,
        result.reference,
        settings
      );

      // Update order based on provider result
      const finalStatus = providerResult.isManual ? 'onPending' : 
                          providerResult.status || 'processing';

      await OrderBoris.findByIdAndUpdate(
        result.order._id,
        {
          status: finalStatus,
          provider: providerResult.provider,
          apiResponse: providerResult.data || null,
          apiOrderId: providerResult.orderId || providerResult.vendorTranxId || null
        }
      );

      // If provider failed and it wasn't manual, refund
      if (!providerResult.success && !providerResult.isManual) {
        await refundOrder(result.order._id, result.order.price);
        
        return res.status(502).json({
          status: 'error',
          message: 'Order processing failed',
          code: 'PROVIDER_ERROR',
          error: providerResult.error?.message,
          refunded: true
        });
      }

      res.status(201).json({
        status: 'success',
        message: 'Order placed successfully',
        data: {
          orderId: result.order._id,
          reference: result.reference,
          status: finalStatus,
          networkKey: networkKey,
          recipient: recipient,
          capacity: numericCapacity,
          price: result.order.price,
          balance: result.newBalance,
          provider: providerResult.provider,
          createdAt: result.order.createdAt
        }
      });

    } catch (error) {
      console.error('Purchase error:', error);
      
      if (error.message.includes('not found')) {
        return res.status(404).json({
          status: 'error',
          message: error.message,
          code: 'NOT_FOUND'
        });
      }
      
      if (error.message.includes('Insufficient balance')) {
        return res.status(400).json({
          status: 'error',
          message: error.message,
          code: 'INSUFFICIENT_BALANCE'
        });
      }
      
      if (error.message.includes('not available')) {
        return res.status(400).json({
          status: 'error',
          message: error.message,
          code: 'BUNDLE_NOT_AVAILABLE'
        });
      }
      
      res.status(500).json({
        status: 'error',
        message: 'Order processing failed',
        code: 'INTERNAL_ERROR',
        error: error.message
      });
    } finally {
      await session.endSession();
    }
  })
);

// Refund helper function
async function refundOrder(orderId, amount) {
  const session = await mongoose.startSession();
  
  try {
    await session.withTransaction(async () => {
      const order = await OrderBoris.findByIdAndUpdate(
        orderId,
        { 
          status: 'failed',
          failedAt: new Date()
        },
        { session, new: true }
      );
      
      if (order) {
        const user = await BorisUser.findById(order.user).session(session);
        if (user) {
          const balanceBefore = user.wallet.balance;
          const balanceAfter = balanceBefore + amount;
          
          user.wallet.balance = balanceAfter;
          user.wallet.transactions.push({
            type: 'credit',
            amount: amount,
            description: `Refund for failed order: ${order.reference}`,
            reference: `REFUND-${order.transactionReference}`,
            timestamp: new Date(),
            status: 'completed',
            balanceBefore,
            balanceAfter
          });
          user.markModified('wallet');
          await user.save({ session });
        }
      }
    });
  } catch (error) {
    console.error('Refund error:', error);
  } finally {
    await session.endSession();
  }
}

// ============================================
// ORDER STATUS
// ============================================
router.get('/orders/:reference', 
  authenticateApiKey, 
  asyncHandler(async (req, res) => {
    const { reference } = req.params;

    const order = await OrderBoris.findOne({ 
      reference: reference,
      user: req.developer._id
    });
    
    if (!order) {
      return res.status(404).json({
        status: 'error',
        message: 'Order not found',
        code: 'ORDER_NOT_FOUND'
      });
    }

    res.json({
      status: 'success',
      data: {
        orderId: order._id,
        reference: order.reference,
        status: order.status,
        networkKey: order.networkKey,
        recipient: order.recipient,
        capacity: order.capacity,
        price: order.price,
        provider: order.provider,
        createdAt: order.createdAt,
        completedAt: order.completedAt
      }
    });
  })
);

// ============================================
// TRANSACTION HISTORY
// ============================================
router.get('/transactions', 
  authenticateApiKey, 
  asyncHandler(async (req, res) => {
    const { 
      page = 1, 
      limit = 20, 
      status,
      networkKey,
      startDate,
      endDate
    } = req.query;
    
    const pageNum = parseInt(page);
    const limitNum = Math.min(parseInt(limit), 100);
    
    // Build filter
    const filter = { user: req.developer._id };
    
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
        filter.createdAt.$lte = new Date(endDate);
      }
    }
    
    // Get orders
    const orders = await OrderBoris.find(filter)
      .sort({ createdAt: -1 })
      .skip((pageNum - 1) * limitNum)
      .limit(limitNum)
      .select('reference status networkKey recipient capacity price provider createdAt completedAt');

    const total = await OrderBoris.countDocuments(filter);

    // Get statistics
    const stats = await OrderBoris.aggregate([
      { $match: { user: mongoose.Types.ObjectId(req.developer._id) } },
      {
        $group: {
          _id: null,
          totalSpent: { $sum: '$price' },
          totalOrders: { $sum: 1 },
          completedOrders: { 
            $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
          },
          failedOrders: { 
            $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
          },
          pendingOrders: { 
            $sum: { $cond: [{ $in: ['$status', ['pending', 'processing', 'onPending']] }, 1, 0] }
          }
        }
      }
    ]);

    res.json({
      status: 'success',
      data: {
        transactions: orders,
        pagination: {
          currentPage: pageNum,
          totalPages: Math.ceil(total / limitNum),
          totalItems: total,
          itemsPerPage: limitNum
        },
        statistics: stats[0] || {
          totalSpent: 0,
          totalOrders: 0,
          completedOrders: 0,
          failedOrders: 0,
          pendingOrders: 0
        }
      }
    });
  })
);

// ============================================
// HEALTH CHECK
// ============================================
router.get('/health', async (req, res) => {
  try {
    const dbState = mongoose.connection.readyState;
    const dbHealthy = dbState === 1;
    
    res.status(dbHealthy ? 200 : 503).json({
      status: dbHealthy ? 'healthy' : 'unhealthy',
      timestamp: new Date().toISOString(),
      database: {
        connected: dbHealthy,
        state: ['disconnected', 'connected', 'connecting', 'disconnecting'][dbState]
      },
      version: '3.0.0'
    });
  } catch (error) {
    res.status(503).json({
      status: 'error',
      message: 'Health check failed',
      error: error.message
    });
  }
});

// ============================================
// API DOCUMENTATION
// ============================================
router.get('/docs', (req, res) => {
  res.json({
    status: 'success',
    data: {
      version: '3.0.0',
      baseUrl: '/api/v1',
      authentication: {
        type: 'API Key',
        header: 'x-api-key',
        obtainKey: 'POST /api/v1/generate-key'
      },
      endpoints: {
        authentication: {
          generateKey: {
            method: 'POST',
            path: '/generate-key',
            body: {
              email: 'string',
              password: 'string'
            }
          }
        },
        wallet: {
          getBalance: {
            method: 'GET',
            path: '/wallet/balance',
            headers: { 'x-api-key': 'required' }
          }
        },
        networks: {
          list: {
            method: 'GET',
            path: '/networks',
            headers: { 'x-api-key': 'required' }
          }
        },
        orders: {
          create: {
            method: 'POST',
            path: '/purchase',
            headers: { 'x-api-key': 'required' },
            body: {
              networkKey: 'string (YELLO|AT_PREMIUM|TELECEL|AT_BIGTIME)',
              recipient: 'string (Ghana phone number)',
              capacity: 'number (GB)'
            }
          },
          getStatus: {
            method: 'GET',
            path: '/orders/:reference',
            headers: { 'x-api-key': 'required' }
          },
          listTransactions: {
            method: 'GET',
            path: '/transactions',
            headers: { 'x-api-key': 'required' },
            query: {
              page: 'number (optional)',
              limit: 'number (optional, max 100)',
              status: 'string (optional)',
              networkKey: 'string (optional)',
              startDate: 'date (optional)',
              endDate: 'date (optional)'
            }
          }
        },
        health: {
          check: {
            method: 'GET',
            path: '/health'
          }
        }
      },
      statusCodes: {
        200: 'Success',
        201: 'Created',
        400: 'Bad Request',
        401: 'Unauthorized',
        403: 'Forbidden',
        404: 'Not Found',
        409: 'Conflict (Duplicate)',
        429: 'Too Many Requests',
        500: 'Internal Server Error',
        502: 'Bad Gateway (Provider Error)',
        503: 'Service Unavailable'
      },
      rateLimits: {
        purchase: '5 requests per minute',
        keyGeneration: '3 requests per hour'
      }
    }
  });
});

module.exports = router;