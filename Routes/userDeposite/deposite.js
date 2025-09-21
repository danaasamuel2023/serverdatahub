// payment.routes.js
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const axios = require('axios');
const mongoose = require('mongoose');

// Import models from schemas file
const { BorisUser, SystemSettings } = require('../../schema/schema');

// Import middleware
const {
  loadSystemSettings,
  authenticate,
  validatePaymentRequest,
  verifyWebhookSignature,
  rateLimit,
  asyncHandler,
  errorHandler
} = require('../../middleware/middleware');

// Apply settings middleware to all routes
router.use(loadSystemSettings);

// Optional: SMS sending function
const sendSMS = async (phoneNumber, message) => {
  try {
    const response = await axios.get('https://sms.arkesel.com/sms/api', {
      params: {
        action: 'send-sms',
        api_key: process.env.ARKESEL_API_KEY || 'QkNhS0l2ZUZNeUdweEtmYVRUREg',
        to: phoneNumber,
        from: 'DataHubGh',
        sms: message
      },
      timeout: 10000
    });
    console.log('SMS sent to:', phoneNumber);
    return { success: true };
  } catch (error) {
    console.error('SMS Error:', error.message);
    return { success: false };
  }
};

// ============================================
// HELPER FUNCTIONS
// ============================================

// Calculate fees using system settings
const calculateFees = (amount, settings) => {
  const feeConfig = settings.payment.processingFees;
  
  if (!feeConfig.enabled) {
    return {
      desiredAmount: parseFloat(amount),
      fee: 0,
      totalPayment: parseFloat(amount)
    };
  }
  
  const fee = (amount * feeConfig.percentage / 100) + feeConfig.fixed;
  const roundedFee = Math.round(fee * 100) / 100;
  
  if (feeConfig.whoPays === 'customer') {
    // Customer pays the fee on top
    return {
      desiredAmount: parseFloat(amount),
      fee: roundedFee,
      totalPayment: parseFloat(amount) + roundedFee
    };
  } else {
    // Merchant bears the fee
    return {
      desiredAmount: parseFloat(amount) - roundedFee,
      fee: roundedFee,
      totalPayment: parseFloat(amount)
    };
  }
};

// Create Paystack client
const getPaystackClient = (settings) => {
  const client = axios.create({
    baseURL: 'https://api.paystack.co',
    timeout: 30000,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${settings.payment.paystack.secretKey}`
    }
  });
  
  // Add logging in development
  if (process.env.NODE_ENV === 'development') {
    client.interceptors.request.use(request => {
      console.log('Paystack Request:', request.url);
      return request;
    });
  }
  
  return client;
};

// ============================================
// UNIFIED PAYMENT PROCESSING FUNCTION
// ============================================
async function processPaymentCredit(userId, reference, paymentData, settings) {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const user = await BorisUser.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      return { success: false, error: 'User not found' };
    }

    const transactionIndex = user.wallet.transactions.findIndex(
      t => t.reference === reference
    );

    if (transactionIndex === -1) {
      await session.abortTransaction();
      return { success: false, error: 'Transaction not found' };
    }

    // Check if already completed
    if (user.wallet.transactions[transactionIndex].status === 'completed') {
      await session.abortTransaction();
      return { 
        success: true, 
        alreadyProcessed: true,
        balance: user.wallet.balance,
        transaction: user.wallet.transactions[transactionIndex]
      };
    }

    // Check payment status
    if (paymentData.status !== 'success') {
      user.wallet.transactions[transactionIndex].status = 'failed';
      user.wallet.transactions[transactionIndex].failedAt = new Date();
      user.markModified('wallet.transactions');
      await user.save({ session });
      await session.commitTransaction();
      return { success: false, error: 'Payment not successful on Paystack' };
    }

    // Calculate amounts
    const totalPaid = paymentData.amount / 100; // Convert from kobo
    const desiredAmount = parseFloat(
      paymentData.metadata?.desiredAmount || 
      user.wallet.transactions[transactionIndex].desiredAmount ||
      totalPaid
    );
    const fee = totalPaid - desiredAmount;

    // Track balance changes
    const balanceBefore = user.wallet.balance;
    const balanceAfter = balanceBefore + desiredAmount;

    // Update transaction with all details
    const updatedTransaction = {
      type: 'credit',
      amount: desiredAmount,
      desiredAmount: desiredAmount,
      totalPayment: totalPaid,
      processingFee: fee,
      description: `Deposit via ${paymentData.channel || 'Paystack'}`,
      timestamp: new Date(),
      status: 'completed',
      completedAt: new Date(),
      channel: paymentData.channel,
      reference: reference,
      paystackReference: paymentData.reference,
      processedBy: paymentData.processedBy || 'system',
      balanceBefore: balanceBefore,
      balanceAfter: balanceAfter
    };

    // Replace the transaction
    user.wallet.transactions.splice(transactionIndex, 1, updatedTransaction);
    user.wallet.balance = balanceAfter;
    user.markModified('wallet');
    
    await user.save({ session, validateBeforeSave: false });
    await session.commitTransaction();

    console.log('✅ Payment processed successfully:', {
      userId,
      reference,
      amount: desiredAmount,
      newBalance: balanceAfter
    });

    // Send SMS notification
    if (user.phoneNumber) {
      const message = `Payment successful! Amount: GHS ${desiredAmount.toFixed(2)}, New balance: GHS ${balanceAfter.toFixed(2)}`;
      sendSMS(user.phoneNumber, message);
    }

    return {
      success: true,
      balance: balanceAfter,
      previousBalance: balanceBefore,
      amountCredited: desiredAmount,
      totalPaid,
      fee,
      transaction: updatedTransaction
    };

  } catch (error) {
    await session.abortTransaction();
    console.error('Payment processing error:', error);
    throw error;
  } finally {
    session.endSession();
  }
}

// ============================================
// INITIALIZE PAYMENT
// ============================================
router.post('/initialize-payment',
  authenticate,
  rateLimit({ max: 10, windowMs: 15 * 60 * 1000 }),
  validatePaymentRequest,
  asyncHandler(async (req, res) => {
    const { amount, email, callback_url } = req.body;
    const userId = req.userId;
    const user = req.paymentUser;
    const settings = req.systemSettings;

    // Calculate fees
    const { desiredAmount, fee, totalPayment } = calculateFees(parseFloat(amount), settings);
    
    // Generate unique reference
    const reference = `PAY-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const amountInKobo = Math.round(totalPayment * 100);

    // Create pending transaction
    const balanceBefore = user.wallet.balance;
    
    user.wallet.transactions.push({
      type: 'credit',
      amount: 0, // Will be updated when completed
      desiredAmount,
      totalPayment,
      processingFee: fee,
      description: 'Pending payment',
      timestamp: new Date(),
      reference,
      status: 'pending',
      balanceBefore,
      balanceAfter: null,
      initializedAt: new Date()
    });
    
    user.markModified('wallet.transactions');
    await user.save();

    // Initialize with Paystack
    const paystackClient = getPaystackClient(settings);
    
    try {
      const response = await paystackClient.post('/transaction/initialize', {
        email: email || user.email,
        amount: amountInKobo,
        currency: settings.general.currency || 'GHS',
        reference,
        callback_url: callback_url || `https://console.datahubgh.com/deposit/verify`,
        metadata: {
          userId: userId,
          userEmail: user.email,
          phoneNumber: user.phoneNumber,
          desiredAmount: desiredAmount,
          processingFee: fee
        } 
      });

      return res.json({
        status: 'success',
        message: 'Payment initialized successfully',
        data: {
          authorization_url: response.data.data.authorization_url,
          access_code: response.data.data.access_code,
          reference,
          desiredAmount,
          processingFee: fee,
          totalPayment,
          currentBalance: user.wallet.balance
        }
      });

    } catch (error) {
      // Remove pending transaction on failure
      user.wallet.transactions = user.wallet.transactions.filter(
        t => t.reference !== reference
      );
      user.markModified('wallet.transactions');
      await user.save();

      console.error('Paystack initialization error:', error.response?.data);
      throw new Error(error.response?.data?.message || 'Failed to initialize payment');
    }
  })
);

// ============================================
// VERIFY PAYMENT
// ============================================
router.post('/verify-payment',
  authenticate,
  rateLimit({ max: 20, windowMs: 15 * 60 * 1000 }),
  asyncHandler(async (req, res) => {
    const { reference } = req.body;
    const userId = req.userId;
    const settings = req.systemSettings;

    if (!reference) {
      return res.status(400).json({
        status: 'error',
        message: 'Reference is required'
      });
    }

    // Check current status
    const user = await BorisUser.findById(userId);
    const transaction = user.wallet.transactions.find(t => t.reference === reference);
    
    if (!transaction) {
      return res.status(404).json({
        status: 'error',
        message: 'Transaction not found'
      });
    }

    if (transaction.status === 'completed') {
      return res.json({
        status: 'success',
        message: 'Payment already processed',
        data: {
          reference,
          transactionStatus: 'completed',
          amount: transaction.amount,
          currentBalance: user.wallet.balance,
          alreadyProcessed: true
        }
      });
    }

    // Verify with Paystack
    const paystackClient = getPaystackClient(settings);
    
    try {
      const response = await paystackClient.get(`/transaction/verify/${reference}`);
      const paymentData = response.data.data;

      // Process payment
      paymentData.processedBy = 'manual_verification';
      const result = await processPaymentCredit(userId, reference, paymentData, settings);

      if (result.success) {
        return res.json({
          status: 'success',
          message: result.alreadyProcessed ? 'Payment already processed' : 'Payment verified successfully',
          data: {
            reference,
            transactionStatus: 'completed',
            amount: result.amountCredited || result.transaction.amount,
            totalPayment: result.totalPaid,
            processingFee: result.fee,
            previousBalance: result.previousBalance,
            currentBalance: result.balance,
            channel: paymentData.channel,
            alreadyProcessed: result.alreadyProcessed
          }
        });
      } else {
        throw new Error(result.error);
      }

    } catch (error) {
      console.error('Verification error:', error);
      
      if (error.response?.status === 404) {
        return res.status(404).json({
          status: 'error',
          message: 'Payment not found on Paystack'
        });
      }
      
      return res.status(500).json({
        status: 'error',
        message: error.message || 'Verification failed'
      });
    }
  })
);

// ============================================
// WEBHOOK HANDLER
// ============================================
router.post('/webhook',
  express.raw({ type: 'application/json' }),
  verifyWebhookSignature,
  asyncHandler(async (req, res) => {
    const event = req.body;
    const settings = req.systemSettings;
    
    console.log('🔔 Webhook event:', event.event);

    switch (event.event) {
      case 'charge.success':
        const userId = event.data.metadata?.userId || event.data.metadata?.user_id;
        if (userId) {
          event.data.processedBy = 'webhook';
          const result = await processPaymentCredit(userId, event.data.reference, event.data, settings);
          
          if (result.success) {
            console.log(result.alreadyProcessed ? 'Payment already processed' : 'Payment credited via webhook');
          } else {
            console.error('Failed to credit payment:', result.error);
          }
        }
        break;
        
      case 'charge.failed':
        const failedUserId = event.data.metadata?.userId;
        if (failedUserId) {
          const user = await BorisUser.findById(failedUserId);
          if (user) {
            const txIndex = user.wallet.transactions.findIndex(
              t => t.reference === event.data.reference && t.status === 'pending'
            );
            if (txIndex !== -1) {
              user.wallet.transactions[txIndex].status = 'failed';
              user.wallet.transactions[txIndex].failedAt = new Date();
              user.markModified('wallet.transactions');
              await user.save();
            }
          }
        }
        break;
        
      default:
        console.log('Unhandled webhook event:', event.event);
    }

    // Always return 200 to acknowledge receipt
    res.sendStatus(200);
  })
);

// ============================================
// GET WALLET BALANCE
// ============================================
router.get('/wallet',
  authenticate,
  asyncHandler(async (req, res) => {
    const user = await BorisUser.findById(req.userId);
    
    res.json({
      status: 'success',
      data: {
        balance: user.wallet.balance,
        currency: user.wallet.currency || req.systemSettings.general.currency,
        pendingTransactions: user.wallet.transactions.filter(t => t.status === 'pending').length,
        lastTransaction: user.wallet.transactions
          .filter(t => t.status === 'completed')
          .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0] || null
      }
    });
  })
);

// ============================================
// GET TRANSACTIONS
// ============================================
router.get('/transactions',
  authenticate,
  asyncHandler(async (req, res) => {
    const { page = 1, limit = 20, type, status } = req.query;
    const user = await BorisUser.findById(req.userId);
    
    let transactions = [...user.wallet.transactions];
    
    // Filter
    if (type) transactions = transactions.filter(t => t.type === type);
    if (status) transactions = transactions.filter(t => t.status === status);
    
    // Sort by timestamp (newest first)
    transactions.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    // Paginate
    const skip = (page - 1) * limit;
    const paginatedTransactions = transactions.slice(skip, skip + parseInt(limit));
    
    res.json({
      status: 'success',
      data: {
        transactions: paginatedTransactions,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: transactions.length,
          pages: Math.ceil(transactions.length / limit)
        },
        summary: {
          balance: user.wallet.balance,
          totalCredit: transactions
            .filter(t => t.type === 'credit' && t.status === 'completed')
            .reduce((sum, t) => sum + t.amount, 0),
          totalDebit: transactions
            .filter(t => t.type === 'debit' && t.status === 'completed')
            .reduce((sum, t) => sum + t.amount, 0)
        }
      }
    });
  })
);

// Apply error handler
router.use(errorHandler);

module.exports = router;