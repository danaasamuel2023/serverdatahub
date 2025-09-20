// server.js - Main server file
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// Import database connection
const ConnectDB = require('./Connection/Connect');

// Import models and initialization functions
const { 
  SystemSettings, 
  NetworkConfig,
  Admin,
  initializeDefaultNetworks 
} = require('./schema/schema');

// Import routes
const authRoutes = require('./Routes/Auth/auth');
const userRoutes = require('./Routes/user/user');
const orderRoutes = require('./Routes/order/order');
const adminRoutes = require('./Routes/adminRoutes/admin');
const deposit = require('./Routes/userDeposite/deposite');

// Import middleware
const { loadSystemSettings, errorHandler } = require('./middleware/middleware');

// Initialize Express app
const app = express();

// Port configuration
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// ============================================
// MIDDLEWARE CONFIGURATION
// ============================================

// Security middleware
app.use(helmet());

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:3001',
      'https://yourdomain.com' // Replace with your actual domain
    ];
    
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Body parser middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging in development
if (NODE_ENV === 'development') {
  app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
  });
}

// Global rate limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', globalLimiter);

// Trust proxy (for deployment behind reverse proxy)
app.set('trust proxy', 1);

// ============================================
// DATABASE CONNECTION
// ============================================

// MongoDB connection with better configuration
const connectDatabase = async () => {
  try {
    // Use environment variable for production
    const mongoUri = process.env.MONGODB_URI || 
      'mongodb+srv://StudentMarket:StudentMarket@cluster0.ukbatl8.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
    
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    
    console.log('✅ Connected to MongoDB successfully');
    
    // Initialize default data
    await initializeSystemSettings();
    await initializeDefaultNetworks();
    await createDefaultAdmin();
    
    console.log('✅ Default configurations initialized');
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    // Don't exit in development, but exit in production
    if (NODE_ENV === 'production') {
      console.error('Exiting process due to database connection failure');
      process.exit(1);
    }
  }
};

// Initialize system settings (FIXED)
async function initializeSystemSettings() {
  try {
    const existingSettings = await SystemSettings.findOne({ settingKey: 'MAIN_SETTINGS' });
    
    if (!existingSettings) {
      const defaultSettings = new SystemSettings({
        settingKey: 'MAIN_SETTINGS',
        payment: {
          paystack: {
            publicKey: process.env.PAYSTACK_PUBLIC_KEY || 'pk_test_placeholder',  // FIXED: Added placeholder
            secretKey: process.env.PAYSTACK_SECRET_KEY || 'sk_test_placeholder',  // FIXED: Added placeholder
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
            apiKey: process.env.GEONECTECH_API_KEY || '',
            baseUrl: 'https://testhub.geonettech.site/api/v1'
          },
          telecel: {
            enabled: true,
            apiKey: process.env.TELECEL_API_KEY || '8ef44b516735ec9455c4647ae980b445b3bc0be06e5a6095088eaa9cfbeb117e',
            baseUrl: 'https://iget.onrender.com/api/developer'
          },
          fgamail: {
            enabled: true,
            apiKey: process.env.FGAMAIL_API_KEY || '806fc6649c0a9597925dd0339c9b3cd6f7994ba3',
            baseUrl: 'https://fgamall.com/api/v1'
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
          supportEmail: 'support@datahubghana.com',
          supportPhone: '+233000000000',
          currency: 'GHS',
          maintenanceMode: false
        }
      });
      
      await defaultSettings.save();
      console.log('✅ System settings initialized');
    }
  } catch (error) {
    console.error('Error initializing system settings:', error);
    // Continue even if settings fail in development
    if (NODE_ENV === 'production') {
      throw error;
    }
  }
}

// Create default admin account
async function createDefaultAdmin() {
  try {
    const adminExists = await Admin.findOne({ role: 'super_admin' });
    
    if (!adminExists) {
      const defaultAdmin = new Admin({
        username: 'admin',
        email: 'admin@datahubghana.com',
        password: process.env.DEFAULT_ADMIN_PASSWORD || 'Admin@123456', // Change this!
        role: 'super_admin',
        isActive: true
      });
      
      await defaultAdmin.save();
      console.log('✅ Default admin account created');
      console.log('⚠️  IMPORTANT: Change the default admin password immediately!');
    }
  } catch (error) {
    console.error('Error creating default admin:', error);
  }
}

// ============================================
// ROUTES CONFIGURATION
// ============================================

// Health check route
app.get('/health', (req, res) => {
  const healthStatus = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: NODE_ENV,
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  };
  
  res.status(mongoose.connection.readyState === 1 ? 200 : 503).json(healthStatus);
});

// API Documentation route
app.get('/', (req, res) => {
  res.json({
    message: 'DataHub Ghana API',
    version: '3.0.0',
    documentation: '/api/v1/docs',
    health: '/health',
    endpoints: {
      auth: '/api/auth',
      user: '/api/user',
      orders: '/api/orders',
      admin: '/api/admin',
      developer: '/api/v1'
    },
    timestamp: new Date().toISOString()
  });
});

// Mount routes
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/v1', deposit); 

// 404 handler
app.use((req, res, next) => {
  res.status(404).json({
    success: false,
    message: 'Route not found',
    path: req.path,
    method: req.method
  });
});

// Global error handler
app.use(errorHandler);

// ============================================
// GRACEFUL SHUTDOWN
// ============================================

// Handle unhandled promise rejections
process.on('unhandledRejection', (err, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', err);
  // Log the error but don't exit in development
  if (NODE_ENV === 'production') {
    // Close server & exit process
    server.close(() => process.exit(1));
  }
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  // Exit process in both development and production
  process.exit(1);
});

// Graceful shutdown on SIGTERM
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Performing graceful shutdown...');
  server.close(() => {
    console.log('Process terminated');
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
});

// ============================================
// START SERVER
// ============================================

let server;

const startServer = async () => {
  try {
    // Connect to database first
    await connectDatabase();
    
    // Start server
    server = app.listen(PORT, () => {
      console.log('========================================');
      console.log(`🚀 Server is running`);
      console.log(`📍 Port: ${PORT}`);
      console.log(`🌍 Environment: ${NODE_ENV}`);
      console.log(`🔗 URL: http://localhost:${PORT}`);
      console.log(`📚 API Docs: http://localhost:${PORT}/api/v1/docs`);
      console.log('========================================');
    });
    
    // Handle server errors
    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} is already in use`);
        process.exit(1);
      } else {
        console.error('Server error:', error);
      }
    });
    
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Start the application
startServer();

module.exports = app; // For testing purposes