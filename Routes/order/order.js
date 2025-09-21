// order.routes.js - User order routes (COMPLETE WITH STATUS CHECKING)
const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const axios = require('axios');

// Import models from schemas
const { BorisUser, OrderBoris, NetworkConfig, SystemSettings, initializeDefaultNetworks } = require('../../schema/schema');

// Import middleware
const {
  loadSystemSettings,
  authenticate,
  rateLimit,
  asyncHandler,
  errorHandler
} = require('../../middleware/middleware');

// Apply middleware to all routes
router.use(loadSystemSettings);
router.use(authenticate); // All order routes require authentication

// ============================================
// HELPER FUNCTIONS FOR API CALLS
// ============================================

// Check GeoNetTech order status
async function checkGeoNetTechOrderStatus(reference, settings) {
  try {
    const apiKey = settings.providers.geonectech.apiKey;
    const baseUrl = settings.providers.geonectech.baseUrl || 'https://testhub.geonettech.site/api/v1';
    
    console.log(`Checking GeoNetTech order status for reference: ${reference}`);
    
    const response = await axios.get(
      `${baseUrl}/order-status/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${apiKey}`
        },
        timeout: 10000
      }
    );
    
    console.log('GeoNetTech status response:', response.data);
    
    // Map GeoNetTech status to your system status
    let mappedStatus = 'processing';
    const apiStatus = response.data?.status || response.data?.data?.status;
    
    if (apiStatus) {
      switch (apiStatus.toLowerCase()) {
        case 'completed':
        case 'success':
          mappedStatus = 'completed';
          break;
        case 'failed':
        case 'error':
          mappedStatus = 'failed';
          break;
        case 'pending':
          mappedStatus = 'onPending';
          break;
        default:
          mappedStatus = 'processing';
      }
    }
    
    return {
      success: true,
      data: response.data,
      status: mappedStatus,
      apiStatus: apiStatus
    };
  } catch (error) {
    console.error('Error checking GeoNetTech order status:', error.message);
    return {
      success: false,
      error: error.message
    };
  }
}

// Process with GeoNetTech
async function processGeoNetTechOrder(networkKey, recipient, capacity, reference, settings) {
  try {
    const apiKey = settings.providers.geonectech.apiKey;
    const baseUrl = settings.providers.geonectech.baseUrl || 'https://testhub.geonettech.site/api/v1';
    
    const payload = {
      network_key: networkKey,
      ref: reference,
      recipient,
      capacity
    };
    
    console.log(`Processing GeoNetTech order for ${networkKey}: ${capacity}GB to ${recipient}`);
    
    const response = await axios.post(
      `${baseUrl}/placeOrder`,
      payload,
      {
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        },
        timeout: 30000
      }
    );
    
    return {
      success: true,
      provider: 'GEONECTECH',
      data: response.data,
      orderId: response.data.data?.orderId
    };
  } catch (error) {
    console.error('GeoNetTech API error:', error.message);
    return {
      success: false,
      provider: 'GEONECTECH',
      error: {
        message: error.message,
        details: error.response?.data
      }
    };
  }
}

// Process Telecel orders with Telecel API
async function processTelecelDirectOrder(recipient, capacity, reference, settings) {
  try {
    const apiKey = settings.providers.telecel.apiKey;
    const baseUrl = settings.providers.telecel.baseUrl || 'https://iget.onrender.com/api/developer';
    
    const payload = {
      recipientNumber: recipient,
      capacity: capacity,
      bundleType: "Telecel-5959",
      reference: reference
    };
    
    console.log(`Processing Telecel Direct order: ${capacity}GB to ${recipient}`);
    
    const response = await axios.post(
      `${baseUrl}/orders/place`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': apiKey
        },
        timeout: 30000
      }
    );
    
    return {
      success: true,
      provider: 'TELECEL',
      data: response.data,
      orderId: response.data.data?.order?.id,
      apiOrderReference: response.data.data?.order?.orderReference
    };
  } catch (error) {
    console.error('Telecel API error:', error.message);
    return {
      success: false,
      provider: 'TELECEL',
      error: {
        message: error.message,
        details: error.response?.data
      }
    };
  }
}

// Process AT_PREMIUM orders with FGAMAIL API
async function processFGAMAILOrder(recipient, capacity, reference, settings) {
  try {
    const apiKey = settings.providers.fgamail.apiKey;
    const baseUrl = settings.providers.fgamail.baseUrl || 'https://fgamall.com/api/v1';
    
    // Format phone number
    const formattedRecipient = recipient.startsWith('0') ? recipient : `0${recipient.slice(-9)}`;
    
    // Convert GB to MB for AT_PREMIUM API
    const capacityInMB = capacity * 1000;
    
    const payload = {
      recipient_msisdn: formattedRecipient,
      shared_bundle: capacityInMB,
      order_reference: reference
    };
    
    console.log(`Processing FGAMAIL order: ${capacity}GB (${capacityInMB}MB) for ${formattedRecipient}`);
    
    const response = await axios.post(
      `${baseUrl}/buy-ishare-package`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'x-api-key': apiKey
        },
        timeout: 30000
      }
    );
    
    return {
      success: true,
      provider: 'FGAMAIL',
      data: response.data,
      vendorTranxId: response.data.vendorTranxId || null,
      status: response.data.status || 'processing'
    };
  } catch (error) {
    console.error('FGAMAIL API error:', error.message);
    return {
      success: false,
      provider: 'FGAMAIL',
      error: {
        message: error.message,
        details: error.response?.data
      }
    };
  }
}

// Process order with selected provider
async function processOrderWithProvider(provider, networkKey, recipient, capacity, reference, settings) {
  console.log(`Processing order with provider: ${provider}`);
  
  switch (provider) {
    case 'MANUAL':
      // Manual processing - no API call needed
      return {
        success: true,
        provider: 'MANUAL',
        isManual: true,
        status: 'onPending'
      };
      
    case 'GEONECTECH':
      return await processGeoNetTechOrder(networkKey, recipient, capacity, reference, settings);
      
    case 'TELECEL':
      // Only for TELECEL network
      if (networkKey === 'TELECEL') {
        return await processTelecelDirectOrder(recipient, capacity, reference, settings);
      } else {
        // If not TELECEL network, fallback to GeoNetTech
        return await processGeoNetTechOrder(networkKey, recipient, capacity, reference, settings);
      }
      
    case 'FGAMAIL':
      // Only for AT_PREMIUM network
      if (networkKey === 'AT_PREMIUM') {
        return await processFGAMAILOrder(recipient, capacity, reference, settings);
      } else {
        // If not AT_PREMIUM, fallback to GeoNetTech
        return await processGeoNetTechOrder(networkKey, recipient, capacity, reference, settings);
      }
      
    default:
      return {
        success: false,
        error: { message: `Unknown provider: ${provider}` }
      };
  }
}

// Generate order reference
function generateOrderReference() {
  const timestamp = Date.now().toString(36).toUpperCase();
  const random = Math.random().toString(36).substring(2, 8).toUpperCase();
  return `ORD${timestamp}${random}`;
}

// ============================================
// PLACE ORDER - Main order endpoint
// ============================================
router.post('/place',
  rateLimit({ max: 30, windowMs: 60000 }), // 30 orders per minute
  asyncHandler(async (req, res) => {
    const { networkKey, recipient, capacity } = req.body;
    const userId = req.userId; // From authenticate middleware
    const settings = req.systemSettings; // From loadSystemSettings middleware
    const session = await mongoose.startSession();

    try {
      // Validate inputs
      if (!networkKey || !recipient || !capacity) {
        return res.status(400).json({
          success: false,
          message: 'Missing required fields',
          required: ['networkKey', 'recipient', 'capacity']
        });
      }

      // Validate phone number
      const phoneRegex = /^(?:\+233|233|0)(20|23|24|25|26|27|28|29|30|31|32|50|53|54|55|56|57|58|59)\d{7}$/;
      if (!phoneRegex.test(recipient)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid Ghana phone number format'
        });
      }

      const numericCapacity = parseFloat(capacity);
      if (isNaN(numericCapacity) || numericCapacity <= 0) {
        return res.status(400).json({
          success: false,
          message: 'Invalid capacity value'
        });
      }

      const result = await session.withTransaction(async () => {
        // Get user
        const user = await BorisUser.findById(userId).session(session);
        if (!user) {
          throw new Error('User not found');
        }

        if (user.isDisabled) {
          throw new Error(`Account is disabled: ${user.disableReason || 'Contact support'}`);
        }

        // Get network configuration with provider settings
        const network = await NetworkConfig.findOne({ networkKey, isActive: true }).session(session);
        if (!network) {
          throw new Error(`Network ${networkKey} is not available`);
        }

        // Find bundle
        const bundle = network.bundles.find(b => 
          b.capacity === numericCapacity && b.isActive
        );
        
        if (!bundle) {
          throw new Error(`${numericCapacity}GB bundle not available for ${networkKey}`);
        }

        const price = bundle.price;
        const resellerPrice = bundle.resellerPrice;
        const profit = price - resellerPrice;

        // Check balance
        if (user.wallet.balance < price) {
          throw new Error(`Insufficient balance. Need GHS ${price}, have GHS ${user.wallet.balance}`);
        }

        // Track balance changes
        const balanceBefore = user.wallet.balance;
        const balanceAfter = balanceBefore - price;

        // Generate reference
        const reference = generateOrderReference();
        let apiResponse = null;
        let orderId = null;
        let status = 'pending';
        let usedProvider = null;

        // Get provider from network config
        const primaryProvider = network.provider?.primary || 'MANUAL';
        const fallbackProvider = network.provider?.fallback || null;

        console.log(`Network ${networkKey} - Primary: ${primaryProvider}, Fallback: ${fallbackProvider}`);

        // Try primary provider first
        const primaryResult = await processOrderWithProvider(
          primaryProvider,
          networkKey,
          recipient,
          numericCapacity,
          reference,
          settings
        );

        if (primaryResult.success) {
          apiResponse = primaryResult.data;
          usedProvider = primaryResult.provider;
          
          if (primaryResult.isManual) {
            status = 'onPending';
          } else {
            status = primaryResult.status || 'completed';
            orderId = primaryResult.orderId || primaryResult.vendorTranxId;
          }
        } else if (fallbackProvider) {
          // Try fallback provider if primary fails
          console.log(`Primary provider ${primaryProvider} failed, trying fallback ${fallbackProvider}`);
          
          const fallbackResult = await processOrderWithProvider(
            fallbackProvider,
            networkKey,
            recipient,
            numericCapacity,
            reference,
            settings
          );
          
          if (fallbackResult.success) {
            apiResponse = fallbackResult.data;
            usedProvider = fallbackResult.provider;
            
            if (fallbackResult.isManual) {
              status = 'onPending';
            } else {
              status = fallbackResult.status || 'processing';
              orderId = fallbackResult.orderId || fallbackResult.vendorTranxId;
            }
          } else {
            // Both providers failed, create as pending/manual
            console.log('Both providers failed, creating as onPending');
            status = 'onPending';
            usedProvider = 'MANUAL';
          }
        } else {
          // Primary failed and no fallback, create as pending/manual
          console.log(`Primary provider ${primaryProvider} failed, no fallback, creating as onPending`);
          status = 'onPending';
          usedProvider = 'MANUAL';
        }

        // Create order
        const order = new OrderBoris({
          user: userId,
          reference,
          transactionReference: new mongoose.Types.ObjectId().toString(),
          networkKey,
          recipient,
          capacity: numericCapacity,
          price,
          resellerPrice,
          profit,
          status,
          apiResponse,
          apiOrderId: orderId,
          balanceBefore,
          balanceAfter,
          provider: usedProvider
        });

        // Debit wallet with balance tracking
        user.wallet.transactions.push({
          type: 'debit',
          amount: price,
          description: `${networkKey} ${numericCapacity}GB for ${recipient}`,
          reference: order.transactionReference,
          timestamp: new Date(),
          status: 'completed',
          balanceBefore,
          balanceAfter
        });
        user.wallet.balance = balanceAfter;
        user.markModified('wallet');

        await order.save({ session });
        await user.save({ session });

        return {
          order,
          newBalance: balanceAfter
        };
      });

      res.status(201).json({
        success: true,
        message: 'Order placed successfully',
        data: {
          orderId: result.order._id,
          reference: result.order.reference,
          status: result.order.status,
          recipient: result.order.recipient,
          capacity: result.order.capacity,
          price: result.order.price,
          newBalance: result.newBalance,
          provider: result.order.provider,
          createdAt: result.order.createdAt
        }
      });

    } catch (error) {
      console.error('Order placement error:', error);

      if (error.message.includes('disabled')) {
        return res.status(403).json({
          success: false,
          message: error.message
        });
      }

      if (error.message.includes('Insufficient balance')) {
        return res.status(400).json({
          success: false,
          message: error.message
        });
      }

      res.status(500).json({
        success: false,
        message: error.message || 'Failed to place order'
      });
    } finally {
      await session.endSession();
    }
  })
);

// ============================================
// GET USER ORDERS WITH STATUS CHECK FLAG
// ============================================
router.get('/my-orders',
  asyncHandler(async (req, res) => {
    const userId = req.userId;
    const { page = 1, limit = 20, status, startDate, endDate } = req.query;

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

    // Get orders with pagination
    const orders = await OrderBoris.find(filter)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit))
      .select('reference networkKey recipient capacity price status provider createdAt completedAt apiOrderId');

    const totalOrders = await OrderBoris.countDocuments(filter);

    // Add a flag indicating if status can be checked
    const ordersWithStatusCheck = orders.map(order => ({
      ...order.toObject(),
      canCheckStatus: order.provider === 'GEONECTECH' && ['processing', 'onPending'].includes(order.status)
    }));

    // Get summary statistics
    const stats = await OrderBoris.aggregate([
      { $match: { user: new mongoose.Types.ObjectId(userId) } },
      {
        $group: {
          _id: null,
          totalSpent: { $sum: '$price' },
          totalOrders: { $sum: 1 },
          completedOrders: {
            $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
          },
          pendingOrders: {
            $sum: { $cond: [{ $eq: ['$status', 'onPending'] }, 1, 0] }
          },
          processingOrders: {
            $sum: { $cond: [{ $eq: ['$status', 'processing'] }, 1, 0] }
          }
        }
      }
    ]);

    res.json({
      success: true,
      data: {
        orders: ordersWithStatusCheck,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: totalOrders,
          pages: Math.ceil(totalOrders / limit)
        },
        summary: stats[0] || {
          totalSpent: 0,
          totalOrders: 0,
          completedOrders: 0,
          pendingOrders: 0,
          processingOrders: 0
        }
      }
    });
  })
);

// ============================================
// GET ORDER STATUS
// ============================================
router.get('/status/:reference',
  asyncHandler(async (req, res) => {
    const { reference } = req.params;
    const userId = req.userId;

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
      data: {
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
// CHECK ORDER STATUS WITH PROVIDER - ENHANCED
// ============================================
router.get('/check-status/:reference',
  asyncHandler(async (req, res) => {
    const { reference } = req.params;
    const userId = req.userId;
    const settings = req.systemSettings;

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

    // For MANUAL provider, just return current status
    if (order.provider === 'MANUAL') {
      return res.json({
        success: true,
        message: 'Manual order - using system status',
        data: {
          reference: order.reference,
          status: order.status,
          provider: order.provider,
          networkKey: order.networkKey,
          recipient: order.recipient,
          capacity: order.capacity,
          lastChecked: new Date()
        }
      });
    }

    // For GEONECTECH provider, check with their API
    if (order.provider === 'GEONECTECH') {
      const statusCheck = await checkGeoNetTechOrderStatus(order.reference, settings);
      
      if (statusCheck.success) {
        // Update order status if it has changed
        if (statusCheck.status !== order.status) {
          console.log(`Updating order ${reference} status from ${order.status} to ${statusCheck.status}`);
          
          order.status = statusCheck.status;
          if (statusCheck.status === 'completed') {
            order.completedAt = new Date();
          }
          await order.save();
        }
        
        return res.json({
          success: true,
          message: 'Status checked from GeoNetTech',
          data: {
            reference: order.reference,
            status: order.status,
            apiStatus: statusCheck.apiStatus,
            provider: order.provider,
            networkKey: order.networkKey,
            recipient: order.recipient,
            capacity: order.capacity,
            apiOrderId: order.apiOrderId,
            lastChecked: new Date(),
            apiResponse: statusCheck.data
          }
        });
      } else {
        // If API check fails, return current system status
        console.log(`GeoNetTech status check failed for ${reference}, returning system status`);
        return res.json({
          success: true,
          message: 'Using system status (API check failed)',
          data: {
            reference: order.reference,
            status: order.status,
            provider: order.provider,
            networkKey: order.networkKey,
            recipient: order.recipient,
            capacity: order.capacity,
            lastChecked: new Date()
          }
        });
      }
    }

    // For other providers (TELECEL, FGAMAIL), return system status
    // These are typically instant or have their own status mechanisms
    return res.json({
      success: true,
      message: `Using system status for ${order.provider} provider`,
      data: {
        reference: order.reference,
        status: order.status,
        provider: order.provider,
        networkKey: order.networkKey,
        recipient: order.recipient,
        capacity: order.capacity,
        apiOrderId: order.apiOrderId,
        lastChecked: new Date()
      }
    });
  })
);

// ============================================
// GET AVAILABLE NETWORKS AND BUNDLES
// ============================================
router.get('/networks',
  asyncHandler(async (req, res) => {
    try {
      // Get ALL networks, not just active ones
      let networks = await NetworkConfig.find(
        {}, // No filter - get all networks
        'networkKey name bundles provider isActive'
      );

      // If no networks found, initialize them
      if (!networks || networks.length === 0) {
        console.log('No networks found, initializing default networks...');
        await initializeDefaultNetworks();
        
        // Fetch again after initialization
        networks = await NetworkConfig.find(
          {},
          'networkKey name bundles provider isActive'
        );
        
        console.log(`Initialized ${networks.length} networks`);
      }

      // Format networks and handle bundle availability
      const formattedNetworks = networks.map(network => ({
        networkKey: network.networkKey,
        name: network.name,
        isActive: network.isActive, // Include network active status
        provider: {
          primary: network.provider?.primary || 'MANUAL',
          fallback: network.provider?.fallback || null,
          availableProviders: network.provider?.availableProviders || ['MANUAL']
        },
        bundles: network.bundles
          .map(bundle => ({
            capacity: bundle.capacity,
            price: bundle.price,
            // Bundle is only truly active if BOTH network AND bundle are active
            isActive: network.isActive && bundle.isActive,
            originalBundleStatus: bundle.isActive, // Keep original bundle status for reference
            networkInactive: !network.isActive // Flag to indicate if network is the reason for unavailability
          }))
          .sort((a, b) => a.capacity - b.capacity)
      }));

      console.log(`Returning ${formattedNetworks.length} networks with bundles`);

      res.json({
        success: true,
        data: formattedNetworks
      });
    } catch (error) {
      console.error('Error fetching networks:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch networks',
        error: error.message
      });
    }
  })
);

// ============================================
// GET USER DASHBOARD - Today's stats and balance
// ============================================
router.get('/dashboard',
  asyncHandler(async (req, res) => {
    const userId = req.userId;
    
    try {
      // Get user data for wallet balance - using correct field names
      const user = await BorisUser.findById(userId)
        .select('wallet.balance email firstName secondName phoneNumber role business');
      
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      // Get today's start and end timestamps
      const todayStart = new Date();
      todayStart.setHours(0, 0, 0, 0);
      
      const todayEnd = new Date();
      todayEnd.setHours(23, 59, 59, 999);

      // Get today's orders statistics
      const todayStats = await OrderBoris.aggregate([
        {
          $match: {
            user: new mongoose.Types.ObjectId(userId),
            createdAt: {
              $gte: todayStart,
              $lte: todayEnd
            }
          }
        },
        {
          $group: {
            _id: null,
            totalOrders: { $sum: 1 },
            totalSpent: { $sum: '$price' },
            totalProfit: { $sum: '$profit' },
            completedOrders: {
              $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
            },
            pendingOrders: {
              $sum: { $cond: [{ $eq: ['$status', 'onPending'] }, 1, 0] }
            },
            processingOrders: {
              $sum: { $cond: [{ $eq: ['$status', 'processing'] }, 1, 0] }
            },
            failedOrders: {
              $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
            }
          }
        }
      ]);

      // Get recent orders (last 5)
      const recentOrders = await OrderBoris.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(5)
        .select('reference networkKey recipient capacity price status provider createdAt');

      // Get all-time statistics
      const allTimeStats = await OrderBoris.aggregate([
        {
          $match: { user: new mongoose.Types.ObjectId(userId) }
        },
        {
          $group: {
            _id: null,
            totalOrders: { $sum: 1 },
            totalSpent: { $sum: '$price' },
            totalProfit: { $sum: '$profit' },
            averageOrderValue: { $avg: '$price' }
          }
        }
      ]);

      // Get this month's statistics  
      const monthStart = new Date();
      monthStart.setDate(1);
      monthStart.setHours(0, 0, 0, 0);

      const monthStats = await OrderBoris.aggregate([
        {
          $match: {
            user: new mongoose.Types.ObjectId(userId),
            createdAt: { $gte: monthStart }
          }
        },
        {
          $group: {
            _id: null,
            totalOrders: { $sum: 1 },
            totalSpent: { $sum: '$price' },
            totalProfit: { $sum: '$profit' }
          }
        }
      ]);

      // Get last 7 days trend
      const sevenDaysAgo = new Date();
      sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
      sevenDaysAgo.setHours(0, 0, 0, 0);

      const weeklyTrend = await OrderBoris.aggregate([
        {
          $match: {
            user: new mongoose.Types.ObjectId(userId),
            createdAt: { $gte: sevenDaysAgo }
          }
        },
        {
          $group: {
            _id: {
              $dateToString: { format: '%Y-%m-%d', date: '$createdAt' }
            },
            orders: { $sum: 1 },
            spent: { $sum: '$price' }
          }
        },
        {
          $sort: { _id: 1 }
        }
      ]);

      // Format response with correct field names
      const dashboardData = {
        user: {
          email: user.email,
          firstName: user.firstName,
          secondName: user.secondName,
          phoneNumber: user.phoneNumber,
          role: user.role,
          businessName: user.business?.name,
          currentBalance: user.wallet.balance,
          currency: user.wallet.currency
        },
        today: {
          date: new Date().toISOString().split('T')[0],
          totalOrders: todayStats[0]?.totalOrders || 0,
          totalSpent: todayStats[0]?.totalSpent || 0,
          totalProfit: todayStats[0]?.totalProfit || 0,
          completedOrders: todayStats[0]?.completedOrders || 0,
          pendingOrders: todayStats[0]?.pendingOrders || 0,
          processingOrders: todayStats[0]?.processingOrders || 0,
          failedOrders: todayStats[0]?.failedOrders || 0
        },
        thisMonth: {
          totalOrders: monthStats[0]?.totalOrders || 0,
          totalSpent: monthStats[0]?.totalSpent || 0,
          totalProfit: monthStats[0]?.totalProfit || 0
        },
        allTime: {
          totalOrders: allTimeStats[0]?.totalOrders || 0,
          totalSpent: allTimeStats[0]?.totalSpent || 0,
          totalProfit: allTimeStats[0]?.totalProfit || 0,
          averageOrderValue: allTimeStats[0]?.averageOrderValue || 0
        },
        weeklyTrend,
        recentOrders
      };

      res.json({
        success: true,
        data: dashboardData
      });

    } catch (error) {
      console.error('Dashboard fetch error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch dashboard data',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  })
);

// ============================================
// GET QUICK STATS - Simplified version
// ============================================
router.get('/quick-stats',
  asyncHandler(async (req, res) => {
    const userId = req.userId;
    
    try {
      // Get user balance and info
      const user = await BorisUser.findById(userId)
        .select('wallet.balance wallet.currency firstName secondName');
      
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      // Today's date range
      const todayStart = new Date();
      todayStart.setHours(0, 0, 0, 0);
      
      const todayEnd = new Date();
      todayEnd.setHours(23, 59, 59, 999);

      // Count today's orders and sum spent
      const todayOrders = await OrderBoris.aggregate([
        {
          $match: {
            user: new mongoose.Types.ObjectId(userId),
            createdAt: {
              $gte: todayStart,
              $lte: todayEnd
            }
          }
        },
        {
          $group: {
            _id: null,
            count: { $sum: 1 },
            totalSpent: { $sum: '$price' },
            totalProfit: { $sum: '$profit' }
          }
        }
      ]);

      // Get recent wallet transactions (last 5)
      const recentTransactions = user.wallet.transactions
        .sort((a, b) => b.timestamp - a.timestamp)
        .slice(0, 5)
        .map(t => ({
          type: t.type,
          amount: t.amount,
          description: t.description,
          status: t.status,
          timestamp: t.timestamp,
          balanceBefore: t.balanceBefore,
          balanceAfter: t.balanceAfter
        }));

      res.json({
        success: true,
        data: {
          userName: `${user.firstName} ${user.secondName}`,
          walletBalance: user.wallet.balance,
          currency: user.wallet.currency,
          todayOrderCount: todayOrders[0]?.count || 0,
          todayAmountSpent: todayOrders[0]?.totalSpent || 0,
          todayProfit: todayOrders[0]?.totalProfit || 0,
          recentTransactions,
          timestamp: new Date()
        }
      });

    } catch (error) {
      console.error('Quick stats error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch stats',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  })
);

// ============================================
// GET WALLET HISTORY - For transaction tracking
// ============================================
router.get('/wallet-history',
  asyncHandler(async (req, res) => {
    const userId = req.userId;
    const { page = 1, limit = 20, type, status } = req.query;
    
    try {
      const user = await BorisUser.findById(userId)
        .select('wallet.transactions wallet.balance');
      
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      // Filter transactions
      let transactions = user.wallet.transactions;
      
      if (type) {
        transactions = transactions.filter(t => t.type === type);
      }
      
      if (status) {
        transactions = transactions.filter(t => t.status === status);
      }
      
      // Sort by timestamp (newest first)
      transactions.sort((a, b) => b.timestamp - a.timestamp);
      
      // Paginate
      const startIndex = (page - 1) * limit;
      const endIndex = startIndex + parseInt(limit);
      const paginatedTransactions = transactions.slice(startIndex, endIndex);
      
      res.json({
        success: true,
        data: {
          currentBalance: user.wallet.balance,
          transactions: paginatedTransactions,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total: transactions.length,
            pages: Math.ceil(transactions.length / limit)
          }
        }
      });
      
    } catch (error) {
      console.error('Wallet history error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch wallet history',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  })
);

// Add this to your order.routes.js file after the regular /place endpoint

// ============================================
// BULK ORDER PLACEMENT - Multiple orders at once
// ============================================
router.post('/place-bulk',
  rateLimit({ max: 10, windowMs: 60000 }), // 10 bulk requests per minute
  asyncHandler(async (req, res) => {
    const { orders, networkKey, capacity } = req.body;
    const userId = req.userId;
    const settings = req.systemSettings;
    const session = await mongoose.startSession();

    try {
      // Validate input
      if (!orders || !Array.isArray(orders) || orders.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'Please provide an array of orders',
          example: {
            orders: [
              { recipient: '0241234567', capacity: 5 },
              { recipient: '0551234567', capacity: 10 }
            ],
            networkKey: 'MTN' // Optional, can be specified per order
          }
        });
      }

      // Limit bulk orders to prevent abuse
      if (orders.length > 50) {
        return res.status(400).json({
          success: false,
          message: 'Maximum 50 orders allowed per bulk request'
        });
      }

      // Validate phone numbers
      const phoneRegex = /^(?:\+233|233|0)(20|23|24|25|26|27|28|29|30|31|32|50|53|54|55|56|57|58|59)\d{7}$/;
      const invalidPhones = orders.filter(o => !phoneRegex.test(o.recipient));
      
      if (invalidPhones.length > 0) {
        return res.status(400).json({
          success: false,
          message: 'Invalid phone numbers detected',
          invalidRecipients: invalidPhones.map(o => o.recipient)
        });
      }

      const result = await session.withTransaction(async () => {
        // Get user
        const user = await BorisUser.findById(userId).session(session);
        if (!user) {
          throw new Error('User not found');
        }

        if (user.isDisabled) {
          throw new Error(`Account is disabled: ${user.disableReason || 'Contact support'}`);
        }

        // Process each order
        const results = {
          successful: [],
          failed: [],
          totalCost: 0,
          totalOrders: orders.length
        };

        // Calculate total cost first to check balance
        let totalCost = 0;
        const orderDetails = [];

        for (const orderItem of orders) {
          const orderNetworkKey = orderItem.networkKey || networkKey;
          const orderCapacity = orderItem.capacity || capacity;

          if (!orderNetworkKey || !orderCapacity) {
            results.failed.push({
              recipient: orderItem.recipient,
              error: 'Missing network or capacity'
            });
            continue;
          }

          // Get network configuration
          const network = await NetworkConfig.findOne({ 
            networkKey: orderNetworkKey, 
            isActive: true 
          }).session(session);
          
          if (!network) {
            results.failed.push({
              recipient: orderItem.recipient,
              error: `Network ${orderNetworkKey} not available`
            });
            continue;
          }

          // Find bundle
          const bundle = network.bundles.find(b => 
            b.capacity === orderCapacity && b.isActive
          );
          
          if (!bundle) {
            results.failed.push({
              recipient: orderItem.recipient,
              error: `${orderCapacity}GB bundle not available for ${orderNetworkKey}`
            });
            continue;
          }

          totalCost += bundle.price;
          orderDetails.push({
            ...orderItem,
            network,
            bundle,
            price: bundle.price,
            resellerPrice: bundle.resellerPrice,
            profit: bundle.price - bundle.resellerPrice
          });
        }

        // Check if user has sufficient balance
        if (user.wallet.balance < totalCost) {
          throw new Error(`Insufficient balance. Need GHS ${totalCost.toFixed(2)}, have GHS ${user.wallet.balance.toFixed(2)}`);
        }

        // Track balance for the entire bulk operation
        const initialBalance = user.wallet.balance;
        let currentBalance = initialBalance;

        // Process each valid order
        for (const orderDetail of orderDetails) {
          try {
            const balanceBefore = currentBalance;
            const balanceAfter = balanceBefore - orderDetail.price;
            const reference = generateOrderReference();

            // Get provider settings
            const primaryProvider = orderDetail.network.provider?.primary || 'MANUAL';
            const fallbackProvider = orderDetail.network.provider?.fallback || null;

            // Try to process with provider
            let apiResponse = null;
            let orderId = null;
            let status = 'pending';
            let usedProvider = null;

            // Try primary provider
            const primaryResult = await processOrderWithProvider(
              primaryProvider,
              orderDetail.networkKey || networkKey,
              orderDetail.recipient,
              orderDetail.capacity || capacity,
              reference,
              settings
            );

            if (primaryResult.success) {
              apiResponse = primaryResult.data;
              usedProvider = primaryResult.provider;
              
              if (primaryResult.isManual) {
                status = 'onPending';
              } else {
                status = primaryResult.status || 'processing';
                orderId = primaryResult.orderId || primaryResult.vendorTranxId;
              }
            } else if (fallbackProvider) {
              // Try fallback provider
              const fallbackResult = await processOrderWithProvider(
                fallbackProvider,
                orderDetail.networkKey || networkKey,
                orderDetail.recipient,
                orderDetail.capacity || capacity,
                reference,
                settings
              );
              
              if (fallbackResult.success) {
                apiResponse = fallbackResult.data;
                usedProvider = fallbackResult.provider;
                
                if (fallbackResult.isManual) {
                  status = 'onPending';
                } else {
                  status = fallbackResult.status || 'processing';
                  orderId = fallbackResult.orderId || fallbackResult.vendorTranxId;
                }
              } else {
                status = 'onPending';
                usedProvider = 'MANUAL';
              }
            } else {
              status = 'onPending';
              usedProvider = 'MANUAL';
            }

            // Create order
            const order = new OrderBoris({
              user: userId,
              reference,
              transactionReference: new mongoose.Types.ObjectId().toString(),
              networkKey: orderDetail.networkKey || networkKey,
              recipient: orderDetail.recipient,
              capacity: orderDetail.capacity || capacity,
              price: orderDetail.price,
              resellerPrice: orderDetail.resellerPrice,
              profit: orderDetail.profit,
              status,
              apiResponse,
              apiOrderId: orderId,
              balanceBefore,
              balanceAfter,
              provider: usedProvider,
              isBulkOrder: true,
              bulkOrderGroup: req.body.bulkOrderId || new mongoose.Types.ObjectId().toString()
            });

            await order.save({ session });
            currentBalance = balanceAfter;

            results.successful.push({
              recipient: orderDetail.recipient,
              reference: order.reference,
              orderId: order._id,
              status: order.status,
              price: order.price,
              provider: usedProvider
            });

          } catch (error) {
            console.error(`Failed to process order for ${orderDetail.recipient}:`, error);
            results.failed.push({
              recipient: orderDetail.recipient,
              error: error.message
            });
          }
        }

        // Update user wallet if any orders were successful
        if (results.successful.length > 0) {
          const totalSpent = results.successful.reduce((sum, o) => sum + o.price, 0);
          
          // Add single bulk transaction to wallet
          user.wallet.transactions.push({
            type: 'debit',
            amount: totalSpent,
            description: `Bulk order: ${results.successful.length} successful orders`,
            reference: `BULK-${Date.now()}`,
            timestamp: new Date(),
            status: 'completed',
            balanceBefore: initialBalance,
            balanceAfter: currentBalance
          });
          
          user.wallet.balance = currentBalance;
          user.markModified('wallet');
          await user.save({ session });

          results.totalCost = totalSpent;
          results.newBalance = currentBalance;
        }

        return results;
      });

      // Prepare response
      const response = {
        success: result.successful.length > 0,
        message: `Bulk order processed: ${result.successful.length} successful, ${result.failed.length} failed`,
        data: {
          summary: {
            totalOrders: result.totalOrders,
            successful: result.successful.length,
            failed: result.failed.length,
            totalCost: result.totalCost,
            newBalance: result.newBalance
          },
          successfulOrders: result.successful,
          failedOrders: result.failed
        }
      };

      if (result.successful.length === 0) {
        return res.status(400).json(response);
      }

      res.status(201).json(response);

    } catch (error) {
      console.error('Bulk order error:', error);

      if (error.message.includes('Insufficient balance')) {
        return res.status(400).json({
          success: false,
          message: error.message
        });
      }

      res.status(500).json({
        success: false,
        message: error.message || 'Failed to process bulk order'
      });
    } finally {
      await session.endSession();
    }
  })
);

// ============================================
// BULK ORDER FROM CSV/FILE
// ============================================
router.post('/place-bulk-csv',
  rateLimit({ max: 5, windowMs: 60000 }), // 5 CSV uploads per minute
  asyncHandler(async (req, res) => {
    const { csvData, networkKey, defaultCapacity } = req.body;
    const userId = req.userId;

    try {
      // Parse CSV data
      // Expected format: "recipient,capacity" or just "recipient" (uses defaultCapacity)
      const lines = csvData.split('\n').filter(line => line.trim());
      const orders = [];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;

        // Skip header if present
        if (i === 0 && line.toLowerCase().includes('recipient')) continue;

        const parts = line.split(',').map(p => p.trim());
        const recipient = parts[0];
        const capacity = parts[1] ? parseFloat(parts[1]) : defaultCapacity;

        if (recipient) {
          orders.push({ recipient, capacity });
        }
      }

      if (orders.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'No valid orders found in CSV data'
        });
      }

      // Process using the bulk endpoint logic
      req.body = { orders, networkKey };
      
      // Call the bulk placement endpoint
      return router.handle(req, res);
      
    } catch (error) {
      console.error('CSV bulk order error:', error);
      res.status(400).json({
        success: false,
        message: 'Failed to process CSV data',
        error: error.message
      });
    }
  })
);

// ============================================
// GET BULK ORDER STATUS
// ============================================
router.get('/bulk-status/:bulkOrderGroup',
  asyncHandler(async (req, res) => {
    const { bulkOrderGroup } = req.params;
    const userId = req.userId;

    const orders = await OrderBoris.find({
      user: userId,
      bulkOrderGroup
    }).select('reference recipient capacity price status provider createdAt');

    if (orders.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Bulk order group not found'
      });
    }

    const summary = {
      total: orders.length,
      completed: orders.filter(o => o.status === 'completed').length,
      pending: orders.filter(o => o.status === 'onPending').length,
      processing: orders.filter(o => o.status === 'processing').length,
      failed: orders.filter(o => o.status === 'failed').length,
      totalCost: orders.reduce((sum, o) => sum + o.price, 0)
    };

    res.json({
      success: true,
      data: {
        bulkOrderGroup,
        summary,
        orders
      }
    });
  })
);

// Apply error handler
router.use(errorHandler);

module.exports = router;