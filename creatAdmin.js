// scripts/add-roles-to-existing-users.js
// Run this script to add roles to existing users without roles

const mongoose = require('mongoose');
require('dotenv').config();

// MongoDB connection - using your specific connection string
const password = 'StudentMarket';
const mongoUri = process.env.MONGODB_URI || 
  `mongodb+srv://StudentMarket:${password}@cluster0.ukbatl8.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Import the BorisUser model
const { BorisUser } = require('./schema/schema');

async function migrateExistingUsers() {
  try {
    console.log('🔄 Starting migration to add roles to existing users...');
    
    // Connect to MongoDB
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('✅ Connected to MongoDB');
    
    // Step 1: Find all users without a role field
    console.log('\n📝 Finding users without roles...');
    const usersWithoutRole = await BorisUser.find({ 
      $or: [
        { role: { $exists: false } },
        { role: null },
        { role: '' }
      ]
    });
    
    console.log(`Found ${usersWithoutRole.length} users without roles`);
    
    if (usersWithoutRole.length === 0) {
      console.log('✅ All users already have roles. No migration needed.');
      return;
    }
    
    // Step 2: Update each user with default values
    let successCount = 0;
    let errorCount = 0;
    const errors = [];
    
    for (const user of usersWithoutRole) {
      try {
        console.log(`\nProcessing user: ${user.email}`);
        
        // Set default role to 'user'
        user.role = 'user';
        
        // Initialize permissions if not exist
        if (!user.permissions || typeof user.permissions !== 'object') {
          user.permissions = {
            canManageUsers: false,
            canManageOrders: false,
            canManageSettings: false,
            canManageNetworks: false,
            canViewReports: false,
            canProcessManualOrders: false,
            canAdjustWallets: false
          };
        }
        
        // Update business type if not set
        if (user.business) {
          if (!user.business.type) {
            user.business.type = 'individual';
          }
          if (user.business.resellerDiscount === undefined) {
            user.business.resellerDiscount = 0;
          }
        }
        
        // Initialize admin fields if not exist
        if (user.adminNotes === undefined) {
          user.adminNotes = null;
        }
        if (user.promotedBy === undefined) {
          user.promotedBy = null;
        }
        if (user.promotedAt === undefined) {
          user.promotedAt = null;
        }
        if (user.lastLogin === undefined) {
          user.lastLogin = null;
        }
        
        // Save the updated user
        await user.save();
        successCount++;
        console.log(`✅ Updated user: ${user.email} with role: ${user.role}`);
        
      } catch (error) {
        errorCount++;
        errors.push({
          user: user.email,
          error: error.message
        });
        console.error(`❌ Failed to update user ${user.email}:`, error.message);
      }
    }
    
    // Step 3: Check for special admin emails to promote
    console.log('\n📝 Checking for admin emails to promote...');
    const adminEmails = process.env.ADMIN_EMAILS 
      ? process.env.ADMIN_EMAILS.split(',').map(e => e.trim().toLowerCase())
      : [];
    
    // Add your known admin emails here
    const defaultAdminEmails = [
      'admin@datahubghana.com',
      // Add other admin emails here
    ];
    
    const allAdminEmails = [...new Set([...adminEmails, ...defaultAdminEmails])];
    
    for (const adminEmail of allAdminEmails) {
      const user = await BorisUser.findOne({ 
        email: adminEmail,
        role: 'user' // Only promote if currently a regular user
      });
      
      if (user) {
        console.log(`\nPromoting ${adminEmail} to admin...`);
        user.role = 'admin';
        
        // Set admin permissions
        user.permissions = {
          canManageUsers: true,
          canManageOrders: true,
          canManageSettings: false, // Only super_admin can manage settings
          canManageNetworks: true,
          canViewReports: true,
          canProcessManualOrders: true,
          canAdjustWallets: true
        };
        
        user.adminNotes = 'Promoted during migration';
        user.promotedAt = new Date();
        
        await user.save();
        console.log(`✅ Promoted ${adminEmail} to admin role`);
      }
    }
    
    // Step 4: Create a super admin if none exists
    console.log('\n📝 Checking for super admin account...');
    const superAdminExists = await BorisUser.findOne({ role: 'super_admin' });
    
    if (!superAdminExists) {
      // Check if the default admin exists and promote them
      const defaultAdmin = await BorisUser.findOne({ 
        email: 'admin@datahubghana.com' 
      });
      
      if (defaultAdmin) {
        console.log('Promoting existing admin to super_admin...');
        defaultAdmin.role = 'super_admin';
        
        // Set all permissions
        Object.keys(defaultAdmin.permissions).forEach(key => {
          defaultAdmin.permissions[key] = true;
        });
        
        defaultAdmin.adminNotes = 'Promoted to super_admin during migration';
        await defaultAdmin.save();
        console.log('✅ Promoted existing admin to super_admin');
      } else {
        console.log('⚠️  No super admin exists. Create one manually or use the full migration script.');
      }
    } else {
      console.log('✅ Super admin account already exists');
    }
    
    // Step 5: Summary
    console.log('\n' + '='.repeat(50));
    console.log('📊 Migration Summary:');
    console.log('='.repeat(50));
    console.log(`✅ Successfully updated: ${successCount} users`);
    if (errorCount > 0) {
      console.log(`❌ Failed updates: ${errorCount} users`);
      console.log('\nErrors:');
      errors.forEach(e => console.log(`  - ${e.user}: ${e.error}`));
    }
    
    // Get role distribution
    const roleDistribution = await BorisUser.aggregate([
      { $group: { _id: '$role', count: { $sum: 1 } } },
      { $sort: { _id: 1 } }
    ]);
    
    console.log('\nUser distribution by role:');
    roleDistribution.forEach(item => {
      console.log(`  ${item._id || 'undefined'}: ${item.count} users`);
    });
    
    const totalUsers = await BorisUser.countDocuments();
    console.log(`\nTotal users in database: ${totalUsers}`);
    
    // Check if any users still don't have roles
    const remainingWithoutRoles = await BorisUser.countDocuments({
      $or: [
        { role: { $exists: false } },
        { role: null },
        { role: '' }
      ]
    });
    
    if (remainingWithoutRoles > 0) {
      console.log(`\n⚠️  WARNING: ${remainingWithoutRoles} users still don't have roles!`);
    } else {
      console.log('\n✅ All users now have roles assigned!');
    }
    
    console.log('\n' + '='.repeat(50));
    console.log('✅ Migration completed successfully!');
    console.log('='.repeat(50));
    
  } catch (error) {
    console.error('❌ Migration failed:', error);
  } finally {
    await mongoose.disconnect();
    console.log('\n👋 Disconnected from MongoDB');
  }
}

// Run the migration
migrateExistingUsers();