// server.js
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const fs = require('fs');
const path = require('path');
const csv = require('csv-parser');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const fetch = require('node-fetch');
require('dotenv').config();

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://maps.googleapis.com"],
      imgSrc: ["'self'", "data:", "https:", "http:"],
      connectSrc: ["'self'", "https://api.openai.com"]
    }
  }
}));

app.use(compression());
app.use(cors({
  origin: process.env.CLIENT_URL || ['http://localhost:3000', 'http://127.0.0.1:5500'],
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Static files
app.use('/uploads', express.static('uploads'));
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-super-secret-key-2024-tech-girlies-estate',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax'
  },
  store: new session.MemoryStore()
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Login rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts, please try again later.'
});

// Connect to MongoDB
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/techgirlies_estate';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// Enhanced Admin Schema
const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  role: { type: String, default: 'admin' },
  isActive: { type: Boolean, default: true },
  lastLogin: Date,
  loginAttempts: { type: Number, default: 0 },
  lockUntil: Date,
  profile: {
    firstName: String,
    lastName: String,
    phone: String,
    avatar: String
  },
  permissions: [String],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Add method to check if account is locked
adminSchema.methods.isLocked = function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

const Admin = mongoose.model('Admin', adminSchema);

// Enhanced Property Schema
const propertySchema = new mongoose.Schema({
  title: { type: String, required: true, index: true },
  type: { type: String, required: true, enum: ['House', 'Apartment', 'Commercial', 'Land'] },
  status: { type: String, required: true, default: 'Available', enum: ['Available', 'Sold', 'Rented', 'Under Offer'] },
  price: { type: Number, required: true, min: 0 },
  location: { type: String, required: true, index: true },
  coordinates: {
    lat: { type: Number, required: true },
    lng: { type: Number, required: true }
  },
  // Property details
  bedrooms: { type: Number, min: 0 },
  bathrooms: { type: Number, min: 0 },
  squareMeters: { type: Number, min: 0 },
  parkingSpaces: { type: Number, min: 0 },
  yearBuilt: Number,
  // Features
  furnishing: { type: String, enum: ['Furnished', 'Unfurnished', 'Partially Furnished', ''] },
  petFriendly: { type: String, enum: ['Yes', 'No', ''] },
  features: [String],
  amenities: [String],
  // Description
  description: String,
  highlights: [String],
  // Media
  images: [String],
  videos: [String],
  virtualTour: String,
  documents: [String],
  // Owner information
  owner: {
    name: { type: String, required: true },
    phone: { type: String, required: true },
    email: { type: String, required: true },
    address: { type: String, required: true },
    company: String
  },
  // Agent information
  agent: {
    name: String,
    phone: String,
    email: String,
    photo: String
  },
  // Metadata
  isFeatured: { type: Boolean, default: false },
  featuredUntil: Date,
  views: { type: Number, default: 0 },
  likes: { type: Number, default: 0 },
  shares: { type: Number, default: 0 },
  dateAdded: { type: Date, default: Date.now },
  lastModified: { type: Date, default: Date.now },
  expiryDate: Date,
  // SEO
  slug: { type: String, unique: true, sparse: true },
  metaTitle: String,
  metaDescription: String,
  keywords: [String]
});

// Indexes for better performance
propertySchema.index({ status: 1, type: 1 });
propertySchema.index({ price: 1 });
propertySchema.index({ location: 'text', title: 'text', description: 'text' });
propertySchema.index({ 'coordinates': '2dsphere' });

// Pre-save middleware to generate slug
propertySchema.pre('save', function(next) {
  if (this.isModified('title')) {
    this.slug = this.title
      .toLowerCase()
      .replace(/[^a-z0-9 -]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-');
  }
  this.lastModified = Date.now();
  next();
});

const Property = mongoose.model('Property', propertySchema);

// Contact Schema
const contactSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  phone: String,
  subject: String,
  message: { type: String, required: true },
  propertyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Property' },
  type: { type: String, enum: ['general', 'viewing', 'valuation', 'support'], default: 'general' },
  status: { type: String, enum: ['new', 'contacted', 'resolved', 'spam'], default: 'new' },
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  notes: String,
  ipAddress: String,
  userAgent: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Contact = mongoose.model('Contact', contactSchema);

// Activity Log Schema
const activitySchema = new mongoose.Schema({
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  action: { type: String, required: true },
  resource: { type: String, required: true },
  resourceId: mongoose.Schema.Types.ObjectId,
  details: Object,
  ipAddress: String,
  userAgent: String,
  timestamp: { type: Date, default: Date.now }
});

const Activity = mongoose.model('Activity', activitySchema);

// Analytics Schema
const analyticsSchema = new mongoose.Schema({
  date: { type: Date, required: true },
  type: { type: String, required: true }, // 'daily', 'weekly', 'monthly'
  metrics: {
    totalProperties: Number,
    availableProperties: Number,
    soldProperties: Number,
    rentedProperties: Number,
    newContacts: Number,
    totalViews: Number,
    totalLikes: Number,
    revenue: Number
  },
  createdAt: { type: Date, default: Date.now }
});

const Analytics = mongoose.model('Analytics', analyticsSchema);

// Initialize default admin
async function initializeAdmin() {
  try {
    const adminCount = await Admin.countDocuments();
    if (adminCount === 0) {
      const hash = await bcrypt.hash('admin123', 12);
      await new Admin({
        username: 'admin',
        email: 'admin@techgirlies.co.za',
        passwordHash: hash,
        role: 'superadmin',
        profile: {
          firstName: 'System',
          lastName: 'Administrator'
        },
        permissions: ['all']
      }).save();
      console.log('✅ Default admin created: username=admin, password=admin123');
    }
  } catch (error) {
    console.error('❌ Error creating default admin:', error);
  }
}

// Activity logging middleware
async function logActivity(req, action, resource, resourceId = null, details = {}) {
  try {
    await new Activity({
      adminId: req.session.adminId,
      action,
      resource,
      resourceId,
      details,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    }).save();
  } catch (error) {
    console.error('❌ Error logging activity:', error);
  }
}

// Authentication middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.adminId) {
    next();
  } else {
    res.status(401).json({ 
      success: false, 
      message: 'Authentication required' 
    });
  }
}

// Role-based access middleware
function requireRole(role) {
  return (req, res, next) => {
    if (req.session.adminRole === role || req.session.adminRole === 'superadmin') {
      next();
    } else {
      res.status(403).json({ 
        success: false, 
        message: 'Insufficient permissions' 
      });
    }
  };
}

// Permission check middleware
function requirePermission(permission) {
  return async (req, res, next) => {
    try {
      const admin = await Admin.findById(req.session.adminId);
      if (admin && (admin.role === 'superadmin' || admin.permissions.includes(permission) || admin.permissions.includes('all'))) {
        next();
      } else {
        res.status(403).json({ 
          success: false, 
          message: 'Insufficient permissions' 
        });
      }
    } catch (error) {
      res.status(500).json({ 
        success: false, 
        message: 'Server error' 
      });
    }
  };
}

// =================== AUTHENTICATION ROUTES ===================
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const admin = await Admin.findOne({ 
      $or: [{ username }, { email: username }]
    });
    
    if (!admin) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }
    
    // Check if account is locked
    if (admin.isLocked()) {
      return res.status(423).json({ 
        success: false, 
        message: 'Account temporarily locked due to too many failed attempts' 
      });
    }
    
    const isValidPassword = await bcrypt.compare(password, admin.passwordHash);
    
    if (isValidPassword) {
      // Reset login attempts on successful login
      admin.loginAttempts = 0;
      admin.lockUntil = undefined;
      admin.lastLogin = new Date();
      await admin.save();
      
      req.session.adminId = admin._id;
      req.session.adminRole = admin.role;
      req.session.adminPermissions = admin.permissions;
      
      await logActivity(req, 'LOGIN', 'AUTH', admin._id, { username });
      
      res.json({ 
        success: true, 
        message: 'Login successful',
        user: {
          id: admin._id,
          username: admin.username,
          email: admin.email,
          role: admin.role,
          profile: admin.profile,
          permissions: admin.permissions
        }
      });
    } else {
      // Increment failed login attempts
      admin.loginAttempts += 1;
      
      // Lock account after 5 failed attempts for 30 minutes
      if (admin.loginAttempts >= 5) {
        admin.lockUntil = Date.now() + 30 * 60 * 1000; // 30 minutes
      }
      
      await admin.save();
      await logActivity(req, 'LOGIN_FAILED', 'AUTH', null, { username });
      
      res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials',
        attemptsLeft: 5 - admin.loginAttempts
      });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during login' 
    });
  }
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ 
        success: false, 
        message: 'Logout failed' 
      });
    }
    res.json({ 
      success: true, 
      message: 'Logout successful' 
    });
  });
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const admin = await Admin.findById(req.session.adminId).select('-passwordHash');
    if (!admin) {
      return res.status(404).json({ 
        success: false, 
        message: 'Admin not found' 
      });
    }
    res.json({ 
      success: true, 
      user: admin 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Server error' 
    });
  }
});

app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const admin = await Admin.findById(req.session.adminId);
    
    if (!admin) {
      return res.status(404).json({ 
        success: false, 
        message: 'Admin not found' 
      });
    }
    
    const isValid = await bcrypt.compare(currentPassword, admin.passwordHash);
    if (!isValid) {
      return res.status(400).json({ 
        success: false, 
        message: 'Current password is incorrect' 
      });
    }
    
    admin.passwordHash = await bcrypt.hash(newPassword, 12);
    await admin.save();
    
    await logActivity(req, 'CHANGE_PASSWORD', 'AUTH', admin._id);
    
    res.json({ 
      success: true, 
      message: 'Password changed successfully' 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error changing password' 
    });
  }
});

// =================== ADMIN MANAGEMENT ROUTES ===================
app.get('/api/admins', requireAuth, requireRole('superadmin'), async (req, res) => {
  try {
    const admins = await Admin.find().select('-passwordHash');
    res.json({ 
      success: true, 
      data: admins 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching admins' 
    });
  }
});

app.post('/api/admins', requireAuth, requireRole('superadmin'), async (req, res) => {
  try {
    const { username, email, password, role, permissions, profile } = req.body;
    
    const existingAdmin = await Admin.findOne({
      $or: [{ username }, { email }]
    });
    
    if (existingAdmin) {
      return res.status(400).json({ 
        success: false, 
        message: 'Admin with this username or email already exists' 
      });
    }
    
    const hash = await bcrypt.hash(password, 12);
    const newAdmin = new Admin({
      username,
      email,
      passwordHash: hash,
      role: role || 'admin',
      permissions: permissions || ['read'],
      profile: profile || {}
    });
    
    await newAdmin.save();
    await logActivity(req, 'CREATE', 'ADMIN', newAdmin._id, { username, email, role });
    
    res.json({ 
      success: true, 
      message: 'Admin created successfully',
      data: newAdmin 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error creating admin' 
    });
  }
});

app.put('/api/admins/:id', requireAuth, requireRole('superadmin'), async (req, res) => {
  try {
    const { username, email, password, role, permissions, profile, isActive } = req.body;
    
    const updateData = {};
    if (username) updateData.username = username;
    if (email) updateData.email = email;
    if (role) updateData.role = role;
    if (permissions) updateData.permissions = permissions;
    if (profile) updateData.profile = profile;
    if (typeof isActive === 'boolean') updateData.isActive = isActive;
    
    if (password) {
      updateData.passwordHash = await bcrypt.hash(password, 12);
    }
    
    const admin = await Admin.findByIdAndUpdate(
      req.params.id, 
      updateData, 
      { new: true }
    ).select('-passwordHash');
    
    if (!admin) {
      return res.status(404).json({ 
        success: false, 
        message: 'Admin not found' 
      });
    }
    
    await logActivity(req, 'UPDATE', 'ADMIN', admin._id, { username, email, role });
    
    res.json({ 
      success: true, 
      message: 'Admin updated successfully',
      data: admin 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error updating admin' 
    });
  }
});

app.delete('/api/admins/:id', requireAuth, requireRole('superadmin'), async (req, res) => {
  try {
    // Prevent self-deletion
    if (req.params.id === req.session.adminId) {
      return res.status(400).json({ 
        success: false, 
        message: 'Cannot delete your own account' 
      });
    }
    
    const admin = await Admin.findByIdAndDelete(req.params.id);
    
    if (!admin) {
      return res.status(404).json({ 
        success: false, 
        message: 'Admin not found' 
      });
    }
    
    await logActivity(req, 'DELETE', 'ADMIN', req.params.id);
    
    res.json({ 
      success: true, 
      message: 'Admin deleted successfully' 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error deleting admin' 
    });
  }
});

// =================== PROPERTY ROUTES ===================
app.get('/api/properties', async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 12, 
      type, 
      status, 
      location, 
      minPrice, 
      maxPrice,
      bedrooms,
      bathrooms,
      search,
      sortBy = 'dateAdded',
      sortOrder = 'desc',
      featured
    } = req.query;
    
    const filter = {};
    
    // Text search
    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { location: { $regex: search, $options: 'i' } },
        { 'owner.name': { $regex: search, $options: 'i' } }
      ];
    }
    
    // Filters
    if (type) filter.type = type;
    if (status) filter.status = status;
    if (location) filter.location = { $regex: location, $options: 'i' };
    if (bedrooms) filter.bedrooms = { $gte: parseInt(bedrooms) };
    if (bathrooms) filter.bathrooms = { $gte: parseInt(bathrooms) };
    if (featured === 'true') filter.isFeatured = true;
    
    // Price range
    if (minPrice || maxPrice) {
      filter.price = {};
      if (minPrice) filter.price.$gte = parseInt(minPrice);
      if (maxPrice) filter.price.$lte = parseInt(maxPrice);
    }
    
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };
    
    const properties = await Property.find(filter)
      .sort(sort)
      .skip(skip)
      .limit(parseInt(limit))
      .select('-documents -videos'); // Exclude large fields
    
    const total = await Property.countDocuments(filter);
    
    // Increment view counts (simplified - in production, track per user)
    await Property.updateMany(
      { _id: { $in: properties.map(p => p._id) } },
      { $inc: { views: 1 } }
    );
    
    res.json({
      success: true,
      data: properties,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Error fetching properties:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching properties' 
    });
  }
});

app.get('/api/properties/featured', async (req, res) => {
  try {
    const featured = await Property.find({ 
      isFeatured: true,
      status: 'Available',
      $or: [
        { featuredUntil: { $gte: new Date() } },
        { featuredUntil: { $exists: false } }
      ]
    })
    .limit(8)
    .sort({ dateAdded: -1 });
    
    res.json({ 
      success: true, 
      data: featured 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching featured properties' 
    });
  }
});

app.get('/api/properties/search-suggestions', async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.length < 2) {
      return res.json({ success: true, data: [] });
    }
    
    const suggestions = await Property.find({
      $or: [
        { title: { $regex: q, $options: 'i' } },
        { location: { $regex: q, $options: 'i' } }
      ],
      status: 'Available'
    })
    .select('title location type price')
    .limit(10);
    
    res.json({ success: true, data: suggestions });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching search suggestions' 
    });
  }
});

app.get('/api/properties/:id', async (req, res) => {
  try {
    const property = await Property.findById(req.params.id);
    
    if (!property) {
      return res.status(404).json({ 
        success: false, 
        message: 'Property not found' 
      });
    }
    
    // Increment view count
    property.views += 1;
    await property.save();
    
    res.json({ 
      success: true, 
      data: property 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching property' 
    });
  }
});

app.get('/api/properties/slug/:slug', async (req, res) => {
  try {
    const property = await Property.findOne({ slug: req.params.slug });
    
    if (!property) {
      return res.status(404).json({ 
        success: false, 
        message: 'Property not found' 
      });
    }
    
    // Increment view count
    property.views += 1;
    await property.save();
    
    res.json({ 
      success: true, 
      data: property 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching property' 
    });
  }
});

app.post('/api/properties', requireAuth, requirePermission('write_properties'), async (req, res) => {
  try {
    const propertyData = {
      ...req.body,
      lastModified: new Date()
    };
    
    // Generate coordinates if not provided (using a simple geocoding service)
    if (!propertyData.coordinates && propertyData.location) {
      // In production, use a proper geocoding service like Google Maps Geocoding API
      propertyData.coordinates = {
        lat: -25.7479 + (Math.random() - 0.5) * 10,
        lng: 28.2293 + (Math.random() - 0.5) * 10
      };
    }
    
    const property = new Property(propertyData);
    await property.save();
    
    await logActivity(req, 'CREATE', 'PROPERTY', property._id, { title: property.title });
    
    res.status(201).json({ 
      success: true, 
      message: 'Property created successfully',
      data: property 
    });
  } catch (error) {
    console.error('Error creating property:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error creating property' 
    });
  }
});

app.put('/api/properties/:id', requireAuth, requirePermission('write_properties'), async (req, res) => {
  try {
    const propertyData = {
      ...req.body,
      lastModified: new Date()
    };
    
    const property = await Property.findByIdAndUpdate(
      req.params.id, 
      propertyData, 
      { new: true, runValidators: true }
    );
    
    if (!property) {
      return res.status(404).json({ 
        success: false, 
        message: 'Property not found' 
      });
    }
    
    await logActivity(req, 'UPDATE', 'PROPERTY', property._id, { title: property.title });
    
    res.json({ 
      success: true, 
      message: 'Property updated successfully',
      data: property 
    });
  } catch (error) {
    console.error('Error updating property:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error updating property' 
    });
  }
});

app.delete('/api/properties/:id', requireAuth, requirePermission('delete_properties'), async (req, res) => {
  try {
    const property = await Property.findByIdAndDelete(req.params.id);
    
    if (!property) {
      return res.status(404).json({ 
        success: false, 
        message: 'Property not found' 
      });
    }
    
    await logActivity(req, 'DELETE', 'PROPERTY', req.params.id, { title: property.title });
    
    res.json({ 
      success: true, 
      message: 'Property deleted successfully' 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error deleting property' 
    });
  }
});

app.post('/api/properties/:id/like', async (req, res) => {
  try {
    const property = await Property.findByIdAndUpdate(
      req.params.id,
      { $inc: { likes: 1 } },
      { new: true }
    );
    
    if (!property) {
      return res.status(404).json({ 
        success: false, 
        message: 'Property not found' 
      });
    }
    
    res.json({ 
      success: true, 
      message: 'Property liked successfully',
      data: { likes: property.likes }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error liking property' 
    });
  }
});

app.post('/api/properties/:id/share', async (req, res) => {
  try {
    const property = await Property.findByIdAndUpdate(
      req.params.id,
      { $inc: { shares: 1 } },
      { new: true }
    );
    
    if (!property) {
      return res.status(404).json({ 
        success: false, 
        message: 'Property not found' 
      });
    }
    
    res.json({ 
      success: true, 
      message: 'Property share recorded',
      data: { shares: property.shares }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error recording share' 
    });
  }
});

// =================== IMAGE UPLOAD ===================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(uploadsDir, 'properties');
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'property-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
  }
});

app.post('/api/properties/:id/upload', requireAuth, upload.array('images', 10), async (req, res) => {
  try {
    const property = await Property.findById(req.params.id);
    
    if (!property) {
      // Delete uploaded files if property not found
      req.files.forEach(file => {
        fs.unlinkSync(file.path);
      });
      return res.status(404).json({ 
        success: false, 
        message: 'Property not found' 
      });
    }
    
    const newImages = req.files.map(file => `/uploads/properties/${file.filename}`);
    property.images = [...property.images, ...newImages];
    property.lastModified = new Date();
    
    await property.save();
    await logActivity(req, 'UPLOAD_IMAGES', 'PROPERTY', property._id, { 
      imageCount: newImages.length 
    });
    
    res.json({ 
      success: true, 
      message: 'Images uploaded successfully',
      data: newImages 
    });
  } catch (error) {
    // Delete uploaded files on error
    req.files.forEach(file => {
      fs.unlinkSync(file.path);
    });
    res.status(500).json({ 
      success: false, 
      message: 'Error uploading images' 
    });
  }
});

app.delete('/api/properties/:id/images/:imageIndex', requireAuth, async (req, res) => {
  try {
    const property = await Property.findById(req.params.id);
    const imageIndex = parseInt(req.params.imageIndex);
    
    if (!property) {
      return res.status(404).json({ 
        success: false, 
        message: 'Property not found' 
      });
    }
    
    if (imageIndex < 0 || imageIndex >= property.images.length) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid image index' 
      });
    }
    
    const imagePath = property.images[imageIndex];
    // Remove from array
    property.images.splice(imageIndex, 1);
    property.lastModified = new Date();
    
    await property.save();
    
    // Delete physical file
    const fullPath = path.join(__dirname, imagePath);
    if (fs.existsSync(fullPath)) {
      fs.unlinkSync(fullPath);
    }
    
    await logActivity(req, 'DELETE_IMAGE', 'PROPERTY', property._id);
    
    res.json({ 
      success: true, 
      message: 'Image deleted successfully' 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error deleting image' 
    });
  }
});

// =================== CONTACT FORM ROUTES ===================
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, phone, message, subject, propertyId, type } = req.body;
    
    const contact = new Contact({
      name,
      email,
      phone,
      subject,
      message,
      propertyId,
      type: type || 'general',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    await contact.save();
    
    // In production, send email notification here
    console.log('New contact form submission:', {
      name, email, phone, subject, propertyId, type
    });
    
    res.json({ 
      success: true, 
      message: 'Thank you for your message! We will get back to you within 24 hours.',
      data: { id: contact._id }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error processing contact form' 
    });
  }
});

app.get('/api/contacts', requireAuth, requirePermission('read_contacts'), async (req, res) => {
  try {
    const { page = 1, limit = 20, status, type } = req.query;
    
    const filter = {};
    if (status) filter.status = status;
    if (type) filter.type = type;
    
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const contacts = await Contact.find(filter)
      .populate('propertyId', 'title location price')
      .populate('assignedTo', 'username profile.firstName profile.lastName')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Contact.countDocuments(filter);
    
    res.json({
      success: true,
      data: contacts,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching contacts' 
    });
  }
});

app.put('/api/contacts/:id', requireAuth, requirePermission('write_contacts'), async (req, res) => {
  try {
    const { status, assignedTo, notes } = req.body;
    
    const updateData = { updatedAt: new Date() };
    if (status) updateData.status = status;
    if (assignedTo) updateData.assignedTo = assignedTo;
    if (notes !== undefined) updateData.notes = notes;
    
    const contact = await Contact.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    ).populate('propertyId', 'title location price')
     .populate('assignedTo', 'username profile.firstName profile.lastName');
    
    if (!contact) {
      return res.status(404).json({ 
        success: false, 
        message: 'Contact not found' 
      });
    }
    
    await logActivity(req, 'UPDATE', 'CONTACT', contact._id, { status });
    
    res.json({ 
      success: true, 
      message: 'Contact updated successfully',
      data: contact 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error updating contact' 
    });
  }
});

// =================== STATISTICS & ANALYTICS ===================
app.get('/api/statistics', requireAuth, async (req, res) => {
  try {
    const totalProperties = await Property.countDocuments();
    const availableProperties = await Property.countDocuments({ status: 'Available' });
    const soldProperties = await Property.countDocuments({ status: 'Sold' });
    const rentedProperties = await Property.countDocuments({ status: 'Rented' });
    const newContacts = await Contact.countDocuments({ 
      createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } 
    });
    
    const totalValue = await Property.aggregate([
      { $match: { status: 'Available' } },
      { $group: { _id: null, total: { $sum: '$price' } } }
    ]);
    
    const propertiesByType = await Property.aggregate([
      { $group: { _id: '$type', count: { $sum: 1 } } }
    ]);
    
    const propertiesByLocation = await Property.aggregate([
      { $group: { _id: '$location', count: { $sum: 1 } } }
    ]);
    
    const recentActivity = await Activity.find()
      .populate('adminId', 'username profile.firstName profile.lastName')
      .sort({ timestamp: -1 })
      .limit(10);
    
    // Monthly statistics
    const monthlyStats = await Property.aggregate([
      {
        $group: {
          _id: {
            year: { $year: '$dateAdded' },
            month: { $month: '$dateAdded' }
          },
          count: { $sum: 1 },
          totalValue: { $sum: '$price' }
        }
      },
      { $sort: { '_id.year': -1, '_id.month': -1 } },
      { $limit: 12 }
    ]);
    
    res.json({
      success: true,
      data: {
        overview: {
          totalProperties,
          availableProperties,
          soldProperties,
          rentedProperties,
          newContacts,
          totalValue: totalValue[0]?.total || 0
        },
        byType: propertiesByType,
        byLocation: propertiesByLocation,
        monthlyStats,
        recentActivity
      }
    });
  } catch (error) {
    console.error('Error fetching statistics:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching statistics' 
    });
  }
});

app.get('/api/analytics/dashboard', requireAuth, async (req, res) => {
  try {
    // Get today's date and calculate date ranges
    const today = new Date();
    const lastWeek = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
    const lastMonth = new Date(today.getTime() - 30 * 24 * 60 * 60 * 1000);
    
    // Property statistics
    const totalProperties = await Property.countDocuments();
    const newPropertiesThisWeek = await Property.countDocuments({
      dateAdded: { $gte: lastWeek }
    });
    const newPropertiesThisMonth = await Property.countDocuments({
      dateAdded: { $gte: lastMonth }
    });
    
    // Contact statistics
    const totalContacts = await Contact.countDocuments();
    const newContactsThisWeek = await Contact.countDocuments({
      createdAt: { $gte: lastWeek }
    });
    
    // View statistics
    const totalViews = await Property.aggregate([
      { $group: { _id: null, total: { $sum: '$views' } } }
    ]);
    
    const popularProperties = await Property.find()
      .sort({ views: -1 })
      .limit(5)
      .select('title location price views likes');
    
    // Performance metrics
    const conversionRate = totalProperties > 0 ? (soldProperties / totalProperties * 100).toFixed(2) : 0;
    
    res.json({
      success: true,
      data: {
        summary: {
          totalProperties,
          newPropertiesThisWeek,
          newPropertiesThisMonth,
          totalContacts,
          newContactsThisWeek,
          totalViews: totalViews[0]?.total || 0,
          conversionRate: `${conversionRate}%`
        },
        popularProperties,
        quickStats: {
          available: await Property.countDocuments({ status: 'Available' }),
          sold: await Property.countDocuments({ status: 'Sold' }),
          rented: await Property.countDocuments({ status: 'Rented' }),
          underOffer: await Property.countDocuments({ status: 'Under Offer' }),
          featured: await Property.countDocuments({ isFeatured: true })
        }
      }
    });
  } catch (error) {
    console.error('Error fetching dashboard analytics:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching dashboard analytics' 
    });
  }
});

// =================== EXPORT ROUTES ===================
app.get('/api/export/properties/csv', requireAuth, async (req, res) => {
  try {
    const properties = await Property.find();
    
    const csvWriter = createCsvWriter({
      path: 'temp/properties-export.csv',
      header: [
        { id: 'id', title: 'ID' },
        { id: 'title', title: 'Title' },
        { id: 'type', title: 'Type' },
        { id: 'status', title: 'Status' },
        { id: 'price', title: 'Price' },
        { id: 'location', title: 'Location' },
        { id: 'bedrooms', title: 'Bedrooms' },
        { id: 'bathrooms', title: 'Bathrooms' },
        { id: 'squareMeters', title: 'Square Meters' },
        { id: 'parkingSpaces', title: 'Parking Spaces' },
        { id: 'furnishing', title: 'Furnishing' },
        { id: 'petFriendly', title: 'Pet Friendly' },
        { id: 'description', title: 'Description' },
        { id: 'owner.name', title: 'Owner Name' },
        { id: 'owner.phone', title: 'Owner Phone' },
        { id: 'owner.email', title: 'Owner Email' },
        { id: 'owner.address', title: 'Owner Address' },
        { id: 'features', title: 'Features' },
        { id: 'images', title: 'Images' },
        { id: 'dateAdded', title: 'Date Added' },
        { id: 'views', title: 'Views' }
      ]
    });
    
    const records = properties.map(p => ({
      id: p._id,
      title: p.title,
      type: p.type,
      status: p.status,
      price: p.price,
      location: p.location,
      bedrooms: p.bedrooms || 0,
      bathrooms: p.bathrooms || 0,
      squareMeters: p.squareMeters || 0,
      parkingSpaces: p.parkingSpaces || 0,
      furnishing: p.furnishing || '',
      petFriendly: p.petFriendly || '',
      description: p.description || '',
      'owner.name': p.owner.name,
      'owner.phone': p.owner.phone,
      'owner.email': p.owner.email,
      'owner.address': p.owner.address,
      features: p.features.join(', '),
      images: p.images.join(' | '),
      dateAdded: p.dateAdded.toISOString().split('T')[0],
      views: p.views
    }));
    
    await csvWriter.writeRecords(records);
    
    res.download('temp/properties-export.csv', `properties-export-${new Date().toISOString().split('T')[0]}.csv`, (err) => {
      if (err) {
        console.error('Error downloading file:', err);
      }
      // Clean up temporary file
      fs.unlinkSync('temp/properties-export.csv');
    });
    
    await logActivity(req, 'EXPORT', 'PROPERTIES', null, { format: 'CSV', count: properties.length });
  } catch (error) {
    console.error('Error exporting properties:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error exporting properties' 
    });
  }
});

app.get('/api/export/analytics/pdf', requireAuth, async (req, res) => {
  try {
    // This would generate a PDF report using a library like pdfkit or puppeteer
    // For now, we'll return a JSON response
    const stats = await getComprehensiveStats();
    
    res.json({
      success: true,
      message: 'PDF export would be generated here',
      data: stats
    });
    
    await logActivity(req, 'EXPORT', 'ANALYTICS', null, { format: 'PDF' });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error generating PDF report' 
    });
  }
});

async function getComprehensiveStats() {
  const totalProperties = await Property.countDocuments();
  const availableProperties = await Property.countDocuments({ status: 'Available' });
  const totalValue = await Property.aggregate([
    { $match: { status: 'Available' } },
    { $group: { _id: null, total: { $sum: '$price' } } }
  ]);
  
  return {
    totalProperties,
    availableProperties,
    portfolioValue: totalValue[0]?.total || 0,
    generatedAt: new Date().toISOString()
  };
}

// =================== IMPORT ROUTES ===================
app.post('/api/import/properties/csv', requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        success: false, 
        message: 'No file uploaded' 
      });
    }
    
    const properties = [];
    let importedCount = 0;
    let errorCount = 0;
    
    await new Promise((resolve, reject) => {
      fs.createReadStream(req.file.path)
        .pipe(csv())
        .on('data', (data) => {
          try {
            // Parse CSV data into property object
            const property = {
              title: data.Title,
              type: data.Type,
              status: data.Status || 'Available',
              price: parseFloat(data.Price) || 0,
              location: data.Location,
              bedrooms: parseInt(data.Bedrooms) || 0,
              bathrooms: parseInt(data.Bathrooms) || 0,
              squareMeters: parseInt(data['Square Meters']) || 0,
              parkingSpaces: parseInt(data['Parking Spaces']) || 0,
              furnishing: data.Furnishing || '',
              petFriendly: data['Pet Friendly'] || '',
              description: data.Description || '',
              owner: {
                name: data['Owner Name'],
                phone: data['Owner Phone'],
                email: data['Owner Email'],
                address: data['Owner Address']
              },
              features: data.Features ? data.Features.split(',').map(f => f.trim()) : [],
              images: data.Images ? data.Images.split('|').map(img => img.trim()) : [],
              coordinates: {
                lat: -25.7479 + (Math.random() - 0.5) * 10,
                lng: 28.2293 + (Math.random() - 0.5) * 10
              }
            };
            
            properties.push(property);
            importedCount++;
          } catch (error) {
            errorCount++;
            console.error('Error parsing CSV row:', error);
          }
        })
        .on('end', resolve)
        .on('error', reject);
    });
    
    // Insert properties into database
    if (properties.length > 0) {
      await Property.insertMany(properties);
    }
    
    // Clean up uploaded file
    fs.unlinkSync(req.file.path);
    
    await logActivity(req, 'IMPORT', 'PROPERTIES', null, { 
      format: 'CSV', 
      imported: importedCount, 
      errors: errorCount 
    });
    
    res.json({ 
      success: true, 
      message: `Import completed. Successfully imported ${importedCount} properties with ${errorCount} errors.`,
      data: { imported: importedCount, errors: errorCount }
    });
  } catch (error) {
    console.error('Error importing properties:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error importing properties' 
    });
  }
});

// =================== AI CHAT ROUTE ===================
app.post('/api/chat', async (req, res) => {
  try {
    const { message, properties } = req.body;

    if (!process.env.OPENAI_API_KEY) {
      return res.json({ 
        success: true,
        reply: "I'd be happy to help you with property inquiries! Our team will assist you shortly." 
      });
    }

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
      },
      body: JSON.stringify({
        model: "gpt-3.5-turbo",
        messages: [
          { 
            role: "system", 
            content: `You are a real estate assistant for Tech Girlies Estate. 
                     Be helpful, professional, and friendly. 
                     Use this property data if relevant: ${JSON.stringify(properties)}. 
                     Keep responses concise and focused on real estate.` 
          },
          { role: "user", content: message }
        ],
        max_tokens: 150,
        temperature: 0.7
      })
    });

    const data = await response.json();
    
    if (data.choices && data.choices.length > 0) {
      const reply = data.choices[0].message.content;
      res.json({ 
        success: true,
        reply 
      });
    } else {
      res.json({ 
        success: true,
        reply: "Thank you for your message! Our real estate agents will contact you shortly to assist with your inquiry." 
      });
    }
  } catch (error) {
    console.error('Chat error:', error);
    res.json({ 
      success: true,
      reply: "I'm currently unavailable, but our team will be happy to assist you. Please call us at +27 12 345 6789." 
    });
  }
});

// =================== SYSTEM MAINTENANCE ROUTES ===================
app.get('/api/system/health', requireAuth, async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    const memoryUsage = process.memoryUsage();
    const uptime = process.uptime();
    
    res.json({
      success: true,
      data: {
        status: 'healthy',
        database: dbStatus,
        memory: {
          used: Math.round(memoryUsage.heapUsed / 1024 / 1024) + ' MB',
          total: Math.round(memoryUsage.heapTotal / 1024 / 1024) + ' MB'
        },
        uptime: Math.round(uptime) + ' seconds',
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Health check failed' 
    });
  }
});

app.post('/api/system/backup', requireAuth, requireRole('superadmin'), async (req, res) => {
  try {
    // This would create a database backup
    // In production, use proper backup solutions
    const backupData = {
      properties: await Property.find(),
      contacts: await Contact.find(),
      admins: await Admin.find().select('-passwordHash'),
      activities: await Activity.find(),
      backupDate: new Date().toISOString()
    };
    
    const backupDir = path.join(__dirname, 'backups');
    if (!fs.existsSync(backupDir)) {
      fs.mkdirSync(backupDir, { recursive: true });
    }
    
    const backupFile = path.join(backupDir, `backup-${Date.now()}.json`);
    fs.writeFileSync(backupFile, JSON.stringify(backupData, null, 2));
    
    await logActivity(req, 'BACKUP', 'SYSTEM', null);
    
    res.json({ 
      success: true, 
      message: 'Backup created successfully',
      data: { file: backupFile }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error creating backup' 
    });
  }
});

// =================== ERROR HANDLING ===================
app.use((err, req, res, next) => {
  console.error('Error:', err);
  
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ 
        success: false, 
        message: 'File too large. Maximum size is 10MB.' 
      });
    }
  }
  
  res.status(500).json({ 
    success: false, 
    message: 'Internal server error' 
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    success: false, 
    message: 'Endpoint not found' 
  });
});

// =================== START SERVER ===================
const PORT = process.env.PORT || 3000;

async function startServer() {
  await initializeAdmin();
  
  // Create necessary directories
  const dirs = ['uploads/properties', 'temp', 'backups'];
  dirs.forEach(dir => {
    const fullPath = path.join(__dirname, dir);
    if (!fs.existsSync(fullPath)) {
      fs.mkdirSync(fullPath, { recursive: true });
    }
  });
  
  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📊 Admin Dashboard: http://localhost:${PORT}/admin.html`);
    console.log(`🏠 Main Site: http://localhost:${PORT}/index.html`);
    console.log(`🔧 API Base: http://localhost:${PORT}/api`);
  });
}

startServer().catch(console.error);