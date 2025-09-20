const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// ============================================
// SYSTEM SETTINGS SCHEMA (UPDATED)
// Admin configurable settings
// ============================================
const systemSettingsSchema = new mongoose.Schema({
  settingKey: {
    type: String,
    unique: true,
    default: 'MAIN_SETTINGS'
  },
  
  // Payment Settings
  payment: {
    paystack: {
      publicKey: { type: String, required: true },
      secretKey: { type: String, required: true, select: false },
      webhookSecret: { type: String, select: false },
      testMode: { type: Boolean, default: false }
    },
    
    // Processing Fees
    processingFees: {
      enabled: { type: Boolean, default: true },
      percentage: { type: Number, default: 1.5 }, // 1.5% fee
      fixed: { type: Number, default: 0 }, // Fixed fee in GHS
      whoPays: {
        type: String,
        enum: ['customer', 'merchant'],
        default: 'customer' // Customer pays the fees
      },
      minimumDeposit: { type: Number, default: 5 },
      maximumDeposit: { type: Number, default: 5000 }
    }
  },
  
  // API Provider Settings
  providers: {
    geonectech: {
      enabled: { type: Boolean, default: true },
      apiKey: { type: String, select: false },
      apiSecret: { type: String, select: false },
      baseUrl: { type: String, default: 'https://testhub.geonettech.site/api/v1' }
    },
    telecel: {
      enabled: { type: Boolean, default: true },
      apiKey: { type: String, select: false, default: '8ef44b516735ec9455c4647ae980b445b3bc0be06e5a6095088eaa9cfbeb117e' },
      baseUrl: { type: String, default: 'https://iget.onrender.com/api/developer' }
    },
    fgamail: {
      enabled: { type: Boolean, default: true },
      apiKey: { type: String, select: false, default: '806fc6649c0a9597925dd0339c9b3cd6f7994ba3' },
      baseUrl: { type: String, default: 'https://fgamall.com/api/v1' }
    },
    manual: {
      enabled: { type: Boolean, default: true }
    }
  },
  
  // Security Settings
  security: {
    passwordMinLength: { type: Number, default: 6 },
    maxLoginAttempts: { type: Number, default: 5 },
    lockoutDuration: { type: Number, default: 30 }, // minutes
    sessionTimeout: { type: Number, default: 60 } // minutes
  },
  
  // General Settings
  general: {
    siteName: { type: String, default: 'datahubconsole' },
    supportEmail: { type: String, default: 'support@datastore.com' },
    supportPhone: { type: String, default: '+233000000000' },
    currency: { type: String, default: 'GHS' },
    maintenanceMode: { type: Boolean, default: false }
  }
}, {
  timestamps: true
});

// Method to calculate fees
systemSettingsSchema.methods.calculateFees = function(amount, channel = 'card') {
  if (!this.payment.processingFees.enabled) {
    return {
      amount: amount,
      fees: 0,
      total: amount
    };
  }
  
  const percentage = this.payment.processingFees.percentage;
  const fixed = this.payment.processingFees.fixed;
  const fees = (amount * percentage / 100) + fixed;
  const roundedFees = Math.round(fees * 100) / 100;
  
  if (this.payment.processingFees.whoPays === 'customer') {
    return {
      amount: amount,
      fees: roundedFees,
      total: amount + roundedFees
    };
  } else {
    return {
      amount: amount - roundedFees,
      fees: roundedFees,
      total: amount
    };
  }
};

// Create SystemSettings model
const SystemSettings = mongoose.model('SystemSettings', systemSettingsSchema);

// ============================================
// BORIS USER SCHEMA (KEEPING ALL ORIGINAL FIELDS)
// ============================================
const borisUserSchema = new mongoose.Schema({
  // ORIGINAL FIELDS
  firstName: {
    type: String,
    required: [true, 'First name is required'],
    trim: true,
    minLength: [2, 'First name must be at least 2 characters long']
  },
  secondName: {
    type: String,
    required: [true, 'Second name is required'],
    trim: true,
    minLength: [2, 'Second name must be at least 2 characters long']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    validate: {
      validator: function(v) {
        return /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(v);
      },
      message: 'Please enter a valid email address'
    }
  },
  phoneNumber: {
    type: String,
    required: [true, 'Phone number is required'],
    unique: true,
    trim: true,
    validate: {
      validator: function(v) {
        return /^\+?[\d\s-]{10,}$/.test(v);
      },
      message: 'Please enter a valid phone number'
    }
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    select: false,
    minlength: [6, 'Password must be at least 6 characters long']
  },

  // NEW: USER ROLE MANAGEMENT
  role: {
    type: String,
    enum: ['user', 'reseller', 'support', 'admin', 'super_admin'],
    default: 'user'
  },
  
  permissions: {
    // Granular permissions for fine-tuned access control
    canManageUsers: { type: Boolean, default: false },
    canManageOrders: { type: Boolean, default: false },
    canManageSettings: { type: Boolean, default: false },
    canManageNetworks: { type: Boolean, default: false },
    canViewReports: { type: Boolean, default: false },
    canProcessManualOrders: { type: Boolean, default: false },
    canAdjustWallets: { type: Boolean, default: false }
  },

  // Business information
  business: {
    name: {
      type: String,
      required: [true, 'Business name is required'],
      trim: true
    },
    registrationNumber: {
      type: String,
      trim: true
    },
    address: {
      type: String,
      trim: true
    },
    // NEW: Business type for resellers
    type: {
      type: String,
      enum: ['individual', 'company', 'reseller'],
      default: 'individual'
    },
    resellerDiscount: {
      type: Number,
      default: 0, // Percentage discount for resellers
      min: 0,
      max: 50
    }
  },

  // Wallet with transactions
  wallet: {
    balance: {
      type: Number,
      default: 0,
      min: [0, 'Wallet balance cannot be negative'],
      required: true
    },
    currency: {
      type: String,
      default: 'GHS',
      enum: ['GHS', 'USD', 'EUR', 'GBP', 'GHC']
    },
    transactions: [{
      type: {
        type: String,
        enum: ['credit', 'debit'],
        required: true
      },
      amount: {
        type: Number,
        required: true,
        default: 0
      },
      description: {
        type: String,
        default: ''
      },
      timestamp: {
        type: Date,
        default: Date.now
      },
      reference: {
        type: String,
        sparse: true
      },
      paystackReference: {
        type: String,
        sparse: true
      },
      status: {
        type: String,
        enum: ['pending', 'completed', 'failed'],
        default: 'pending',
        required: true
      },
      desiredAmount: {
        type: Number,
        default: 0
      },
      totalPayment: {
        type: Number,
        default: 0
      },
      processingFee: {
        type: Number,
        default: 0
      },
      channel: {
        type: String
      },
      processedBy: {
        type: String,
        enum: ['system', 'webhook', 'manual_verification', 'admin'],
        default: 'system'
      },
      createdAt: {
        type: Date,
        default: Date.now
      },
      initializedAt: {
        type: Date
      },
      completedAt: {
        type: Date
      },
      failedAt: {
        type: Date
      },
      balanceBefore: {
        type: Number,
        default: null
      },
      balanceAfter: {
        type: Number,
        default: null
      }
    }]
  },

  // Account status management
  isDisabled: {
    type: Boolean,
    default: false
  },
  disabledAt: {
    type: Date,
    default: null
  },
  disableReason: {
    type: String,
    trim: true,
    default: null
  },
  disabledBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'BorisUser',
    default: null
  },

  // Password reset fields
  resetPasswordOTP: {
    type: String,
    select: false
  },
  resetPasswordOTPExpiry: {
    type: Date,
    select: false
  },
  lastPasswordReset: {
    type: Date
  },
  
  // Security tracking
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  lastLogin: Date,
  
  // NEW: Admin-specific fields
  adminNotes: {
    type: String,
    default: null
  },
  promotedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'BorisUser',
    default: null
  },
  promotedAt: {
    type: Date,
    default: null
  }
}, { 
  timestamps: true
});

// METHODS

// Check if user is admin
borisUserSchema.methods.isAdmin = function() {
  return ['admin', 'super_admin'].includes(this.role);
};

// Check if user is super admin
borisUserSchema.methods.isSuperAdmin = function() {
  return this.role === 'super_admin';
};

// Check if user has specific permission
borisUserSchema.methods.hasPermission = function(permission) {
  // Super admins have all permissions
  if (this.role === 'super_admin') return true;
  
  // Admins have most permissions
  if (this.role === 'admin') {
    // Admins can't manage settings or other admins
    if (permission === 'canManageSettings') return false;
    return true;
  }
  
  // Support staff have limited permissions
  if (this.role === 'support') {
    const supportPermissions = ['canManageOrders', 'canViewReports', 'canProcessManualOrders'];
    return supportPermissions.includes(permission);
  }
  
  // Check individual permissions for other roles
  return this.permissions[permission] === true;
};

// Promote user to role
borisUserSchema.methods.promoteToRole = async function(newRole, promotedById) {
  const validRoles = ['user', 'reseller', 'support', 'admin', 'super_admin'];
  
  if (!validRoles.includes(newRole)) {
    throw new Error('Invalid role');
  }
  
  this.role = newRole;
  this.promotedBy = promotedById;
  this.promotedAt = new Date();
  
  // Set default permissions based on role
  if (newRole === 'super_admin') {
    // Super admin gets all permissions
    Object.keys(this.permissions).forEach(key => {
      this.permissions[key] = true;
    });
  } else if (newRole === 'admin') {
    // Admin gets most permissions except settings
    this.permissions.canManageUsers = true;
    this.permissions.canManageOrders = true;
    this.permissions.canManageNetworks = true;
    this.permissions.canViewReports = true;
    this.permissions.canProcessManualOrders = true;
    this.permissions.canAdjustWallets = true;
    this.permissions.canManageSettings = false;
  } else if (newRole === 'support') {
    // Support gets limited permissions
    this.permissions.canManageOrders = true;
    this.permissions.canViewReports = true;
    this.permissions.canProcessManualOrders = true;
  } else if (newRole === 'reseller') {
    // Resellers get view permissions
    this.permissions.canViewReports = true;
  } else {
    // Regular users have no admin permissions
    Object.keys(this.permissions).forEach(key => {
      this.permissions[key] = false;
    });
  }
  
  return await this.save();
};

// Get reseller price (if applicable)
borisUserSchema.methods.getPrice = function(standardPrice) {
  if (this.role === 'reseller' && this.business.resellerDiscount > 0) {
    const discount = this.business.resellerDiscount / 100;
    return standardPrice * (1 - discount);
  }
  return standardPrice;
};

// Original methods
borisUserSchema.methods.disable = async function(reason, disabledBy) {
  this.isDisabled = true;
  this.disabledAt = new Date();
  this.disableReason = reason;
  this.disabledBy = disabledBy;
  return await this.save();
};

borisUserSchema.methods.enable = async function() {
  this.isDisabled = false;
  this.disabledAt = null;
  this.disableReason = null;
  this.disabledBy = null;
  return await this.save();
};

borisUserSchema.methods.creditWallet = async function(amount, description, reference) {
  const balanceBefore = this.wallet.balance;
  const balanceAfter = balanceBefore + amount;
  
  const transaction = {
    type: 'credit',
    amount: amount,
    description: description || 'Wallet credit',
    reference: reference,
    status: 'completed',
    completedAt: new Date(),
    timestamp: new Date(),
    balanceBefore: balanceBefore,
    balanceAfter: balanceAfter
  };
  
  this.wallet.transactions.push(transaction);
  this.wallet.balance = balanceAfter;
  
  return await this.save();
};

borisUserSchema.methods.debitWallet = async function(amount, description, reference) {
  if (this.wallet.balance < amount) {
    throw new Error('Insufficient wallet balance');
  }
  
  const balanceBefore = this.wallet.balance;
  const balanceAfter = balanceBefore - amount;
  
  const transaction = {
    type: 'debit',
    amount: amount,
    description: description || 'Wallet debit',
    reference: reference,
    status: 'completed',
    completedAt: new Date(),
    timestamp: new Date(),
    balanceBefore: balanceBefore,
    balanceAfter: balanceAfter
  };
  
  this.wallet.transactions.push(transaction);
  this.wallet.balance = balanceAfter;
  
  return await this.save();
};

borisUserSchema.methods.getPendingTransactions = function() {
  return this.wallet.transactions.filter(t => t.status === 'pending');
};

borisUserSchema.methods.findTransactionByReference = function(reference) {
  return this.wallet.transactions.find(t => t.reference === reference);
};

// Hash password before saving
borisUserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// INDEXES
borisUserSchema.index({ email: 1, phoneNumber: 1 });
borisUserSchema.index({ 'wallet.transactions.reference': 1 });
borisUserSchema.index({ 'wallet.transactions.status': 1 });
borisUserSchema.index({ 'wallet.transactions.timestamp': -1 });
borisUserSchema.index({ role: 1 });

// Create BorisUser model
const BorisUser = mongoose.model('BorisUser', borisUserSchema);

// ============================================
// ORDER BORIS SCHEMA (ALL ORIGINAL FIELDS)
// ============================================
const orderBorisSchema = new mongoose.Schema({
  // ALL YOUR ORIGINAL FIELDS
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'BorisUser',
    required: true
  },
  reference: {
    type: String,
    required: true,
    unique: true
  },
  transactionReference: {
    type: String,
    unique: true,
    required: true,
    default: () => mongoose.Types.ObjectId().toString()
  },
  networkKey: {
    type: String,
    required: true
  },
  recipient: {
    type: String,
    required: true,
    validate: {
      validator: function(v) {
        return /^\+?[\d\s-]{10,}$/.test(v);
      },
      message: 'Please enter a valid phone number'
    }
  },
  capacity: {
    type: Number,
    required: true,
    min: [0.1, 'Capacity must be greater than 0']
  },
  price: {
    type: Number,
    required: true,
    min: [0, 'Price cannot be negative']
  },
  resellerPrice: {  // KEEPING THIS
    type: Number,
    required: true,
    min: [0, 'Reseller price cannot be negative']
  },
  profit: {  // KEEPING THIS
    type: Number,
    required: true
  },
  status: {
    type: String,
    enum: ['onPending', 'processing', 'completed', 'failed', 'pending'],
    default: 'pending'
  },
  apiResponse: {
    type: mongoose.Schema.Types.Mixed,
    default: null
  },
  apiOrderId: {
    type: String,
    sparse: true
  },
  
  // NEW: Balance tracking for orders
  balanceBefore: {
    type: Number,
    default: null
  },
  balanceAfter: {
    type: Number,
    default: null
  },
  
  // UPDATED: Provider tracking
  provider: {
    type: String,
    enum: ['GEONECTECH', 'TELECEL', 'FGAMAIL', 'MANUAL', null],
    default: null
  }
}, {
  timestamps: true
});

// ALL YOUR ORIGINAL INDEXES
orderBorisSchema.index({ reference: 1, user: 1 });
orderBorisSchema.index({ status: 1, createdAt: 1 });
orderBorisSchema.index({ networkKey: 1, capacity: 1 });

// Create OrderBoris model
const OrderBoris = mongoose.model('OrderBoris', orderBorisSchema);

// ============================================
// NETWORK CONFIG SCHEMA (UPDATED WITH FLEXIBLE PROVIDER)
// ============================================
const networkConfigSchema = new mongoose.Schema({
  networkKey: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    enum: ['YELLO', 'AT_PREMIUM', 'TELECEL', 'AT_BIGTIME']
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  bundles: [{
    capacity: { type: Number, required: true },
    price: { type: Number, required: true },
    resellerPrice: { type: Number, required: true },
    isActive: { type: Boolean, default: true }
  }],
  isActive: { type: Boolean, default: true },
  
  // UPDATED: Flexible provider configuration
  provider: {
    // Primary provider to use
    primary: {
      type: String,
      enum: ['GEONECTECH', 'TELECEL', 'FGAMAIL', 'MANUAL'],
      default: 'MANUAL'
    },
    // Fallback provider if primary fails
    fallback: {
      type: String,
      enum: ['GEONECTECH', 'TELECEL', 'FGAMAIL', 'MANUAL', null],
      default: null
    },
    // Available providers for this network (for admin selection)
    availableProviders: [{
      type: String,
      enum: ['GEONECTECH', 'TELECEL', 'FGAMAIL', 'MANUAL']
    }]
  }
}, {
  timestamps: true
});

// Create NetworkConfig model - IMPORTANT: Create it here before it's used
const NetworkConfig = mongoose.model('NetworkConfig', networkConfigSchema);

// ============================================
// ADMIN SCHEMA (NEW - SIMPLE)
// ============================================
const adminSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
    select: false
  },
  role: {
    type: String,
    enum: ['super_admin', 'admin', 'support'],
    default: 'support'
  },
  isActive: { type: Boolean, default: true },
  lastLogin: Date
}, {
  timestamps: true
});

// Hash admin password
adminSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Create Admin model
const Admin = mongoose.model('Admin', adminSchema);

// ============================================
// DEFAULT CONFIGURATIONS WITH UPDATED PROVIDER SETTINGS
// ============================================

// Helper function to calculate reseller price
function getResellerPrice(price) {
  return parseFloat((price * 0.85).toFixed(2));
}

// Default MTN (YELLO) configuration
const defaultMTNConfig = {
  networkKey: 'YELLO',
  name: 'MTN',
  bundles: [
    { capacity: 1, price: 5.00, resellerPrice: 4.20, isActive: true },
    { capacity: 2, price: 10.20, resellerPrice: 8.50, isActive: true },
    { capacity: 3, price: 15.89, resellerPrice: 13.00, isActive: true },
    { capacity: 4, price: 20.00, resellerPrice: 17.00, isActive: true },
    { capacity: 5, price: 25.50, resellerPrice: 21.50, isActive: true },
    { capacity: 6, price: 29.00, resellerPrice: 25.00, isActive: true },
    { capacity: 7, price: 34.00, resellerPrice: 29.00, isActive: true },
    { capacity: 8, price: 40.00, resellerPrice: 34.00, isActive: true },
    { capacity: 10, price: 47.50, resellerPrice: 40.50, isActive: true },
    { capacity: 15, price: 79.50, resellerPrice: 69.50, isActive: true },
    { capacity: 20, price: 90.00, resellerPrice: 78.00, isActive: true },
    { capacity: 25, price: 100.00, resellerPrice: 85.00, isActive: true },
    { capacity: 30, price: 120.00, resellerPrice: 102.00, isActive: true },
    { capacity: 40, price: 158.00, resellerPrice: 135.00, isActive: true },
    { capacity: 50, price: 190.00, resellerPrice: 165.00, isActive: true },
    { capacity: 100, price: 375.00, resellerPrice: 320.00, isActive: true }
  ],
  isActive: true,
  provider: {
    primary: 'MANUAL',
    fallback: 'GEONECTECH',
    availableProviders: ['MANUAL', 'GEONECTECH']
  }
};

// Default AirtelTigo configuration
const defaultATConfig = {
  networkKey: 'AT_PREMIUM',
  name: 'AirtelTigo',
  bundles: defaultMTNConfig.bundles.slice(), // Copy same bundles
  isActive: true,
  provider: {
    primary: 'FGAMAIL',
    fallback: 'GEONECTECH',
    availableProviders: ['FGAMAIL', 'GEONECTECH']
  }
};

// Default Telecel configuration
const defaultTelecelConfig = {
  networkKey: 'TELECEL',
  name: 'Telecel',
  bundles: defaultMTNConfig.bundles.slice(), // Copy same bundles
  isActive: true,
  provider: {
    primary: 'TELECEL',
    fallback: 'GEONECTECH',
    availableProviders: ['TELECEL', 'GEONECTECH', 'MANUAL']
  }
};

// Default AT-BIGTIME configuration
const defaultATBigtimeConfig = {
  networkKey: 'AT_BIGTIME',
  name: 'AT-BIGTIME',
  bundles: [
    { capacity: 10, price: 5.00, resellerPrice: 4.20, isActive: true },
    { capacity: 20, price: 10.20, resellerPrice: 8.50, isActive: true },
    { capacity: 30, price: 15.89, resellerPrice: 13.00, isActive: true },
    { capacity: 40, price: 20.00, resellerPrice: 17.00, isActive: true },
    { capacity: 50, price: 25.50, resellerPrice: 21.50, isActive: true },
    { capacity: 60, price: 29.00, resellerPrice: 25.00, isActive: true },
    { capacity: 70, price: 34.00, resellerPrice: 29.00, isActive: true },
    { capacity: 80, price: 40.00, resellerPrice: 34.00, isActive: true },
    { capacity: 100, price: 47.50, resellerPrice: 40.50, isActive: true },
    { capacity: 150, price: 79.50, resellerPrice: 69.50, isActive: true },
    { capacity: 200, price: 90.00, resellerPrice: 78.00, isActive: true },
    { capacity: 500, price: 190.00, resellerPrice: 165.00, isActive: true }
  ],
  isActive: true,
  provider: {
    primary: 'GEONECTECH',
    fallback: 'MANUAL',
    availableProviders: ['GEONECTECH', 'MANUAL']
  }
};

// Initialize default networks - Now NetworkConfig is defined and available
async function initializeDefaultNetworks() {
  try {
    const networks = [];
    
    for (const config of [defaultMTNConfig, defaultATConfig, defaultTelecelConfig, defaultATBigtimeConfig]) {
      const existing = await NetworkConfig.findOne({ networkKey: config.networkKey });
      if (!existing) {
        networks.push(await NetworkConfig.create(config));
      } else {
        networks.push(existing);
      }
    }
    
    return networks;
  } catch (error) {
    console.error('Error initializing networks:', error);
    throw error;
  }
}

// ============================================
// EXPORTS
// ============================================
module.exports = {
  // Models - Export the already created models
  SystemSettings,
  BorisUser,
  OrderBoris,
  NetworkConfig,
  Admin,
  
  // Helper Functions
  getResellerPrice,
  initializeDefaultNetworks,
  
  // Default Configurations
  defaultMTNConfig,
  defaultATConfig,
  defaultTelecelConfig,
  defaultATBigtimeConfig
};