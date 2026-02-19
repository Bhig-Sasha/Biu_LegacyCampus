require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");
const helmet = require("helmet"); // For security headers
const compression = require("compression"); // For gzip compression
const rateLimit = require("express-rate-limit"); // For rate limiting
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require('fs');

// =============================================
// SEIZETRACK SERVER WITH SUPABASE - PRODUCTION
// =============================================

// Configuration with validation
const requiredEnvVars = ['SUPABASE_URL', 'SUPABASE_ANON_KEY', 'JWT_SECRET'];
for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
        console.error(`❌ Missing required environment variable: ${envVar}`);
        process.exit(1);
    }
}

const config = {
    PORT: process.env.PORT || 5000,
    SUPABASE_URL: process.env.SUPABASE_URL,
    SUPABASE_ANON_KEY: process.env.SUPABASE_ANON_KEY,
    SUPABASE_SERVICE_KEY: process.env.SUPABASE_SERVICE_KEY,
    JWT_SECRET: process.env.JWT_SECRET,
    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '24h',
    NODE_ENV: process.env.NODE_ENV || 'production',
    CLIENT_URL: process.env.CLIENT_URL || 'https://your-frontend-domain.com', // Update this
    API_URL: process.env.API_URL || 'https://your-render-app.onrender.com', // Update this
    RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000, // 15 minutes
    RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX) || 100 // requests per window
};

// Create Express app
const app = express();

// Initialize Supabase client
const supabase = createClient(
    config.SUPABASE_URL,
    config.SUPABASE_ANON_KEY,
    {
        auth: {
            persistSession: false,
            autoRefreshToken: false
        }
    }
);

// Admin Supabase client (for operations that need to bypass RLS)
const supabaseAdmin = config.SUPABASE_SERVICE_KEY 
    ? createClient(config.SUPABASE_URL, config.SUPABASE_SERVICE_KEY, {
        auth: {
            persistSession: false,
            autoRefreshToken: false
        }
    })
    : supabase;

// ========== PRODUCTION MIDDLEWARE ==========

// Security headers with Helmet
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.jsdelivr.net"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.jsdelivr.net"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", config.API_URL, config.SUPABASE_URL]
        }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Compression
app.use(compression());

// Rate limiting
const limiter = rateLimit({
    windowMs: config.RATE_LIMIT_WINDOW,
    max: config.RATE_LIMIT_MAX,
    message: {
        success: false,
        message: 'Too many requests, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter); // Apply rate limiting to all API routes

// CORS configuration for production
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            config.CLIENT_URL,
            config.API_URL,
            'http://localhost:5000',
            'http://localhost:3000'
        ].filter(Boolean);
        
        if (!origin || allowedOrigins.indexOf(origin) !== -1 || config.NODE_ENV !== 'production') {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Body parsing middleware with limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Trust proxy (for Render)
app.set('trust proxy', 1);

// Serve static files with caching
app.use(express.static(path.join(__dirname, 'Public'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0 // Cache static assets for 1 day in production
}));

// Handle SPA routing if needed (remove the catch-all if you want specific routes)
if (process.env.NODE_ENV === 'production') {
  // For any request that doesn't match an API route or static file
  app.get(/^(?!\/api).*/, (req, res) => {
    // Check if the file exists in Public folder
    const filePath = path.join(__dirname, 'Public', req.path === '/' ? 'login.html' : req.path);
    res.sendFile(filePath, (err) => {
      if (err) {
        // If file doesn't exist, serve login.html
        res.sendFile(path.join(__dirname, 'Public', 'login.html'));
      }
    });
  });
}

// Request logging in production
if (config.NODE_ENV === 'production') {
    app.use((req, res, next) => {
        console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
        next();
    });
}

// ========== AUTHENTICATION MIDDLEWARE ==========

const authenticateToken = (req, res, next) => {
    // Skip authentication for public routes
    const publicRoutes = [
        '/api/auth/login',
        '/api/health',
        '/',
        '/login.html',
        '/api/auth/check'
    ];
    
    if (publicRoutes.includes(req.path)) {
        return next();
    }

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        if (req.path.startsWith('/api/')) {
            return res.status(401).json({
                success: false,
                message: 'Access token required. Please login.'
            });
        }
        return res.redirect('/');
    }

    jwt.verify(token, config.JWT_SECRET, (err, user) => {
        if (err) {
            if (req.path.startsWith('/api/')) {
                return res.status(403).json({
                    success: false,
                    message: err.name === 'TokenExpiredError' 
                        ? 'Token has expired' 
                        : 'Invalid token'
                });
            }
            return res.redirect('/');
        }
        req.user = user;
        next();
    });
};

// ========== DATABASE INITIALIZATION ==========

async function initializeDatabase() {
    try {
        console.log('\n🔍 Connecting to Supabase...');
        
        // Test connection with timeout
        const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Connection timeout')), 10000)
        );
        
        const queryPromise = supabase
            .from('users')
            .select('count', { count: 'exact', head: true });
        
        const { error } = await Promise.race([queryPromise, timeoutPromise]);
        
        if (error) {
            console.error('❌ Supabase connection failed:', error.message);
            return false;
        }
        
        console.log('✅ Connected to Supabase successfully!');
        
        // Log environment
        console.log(`🌍 Environment: ${config.NODE_ENV}`);
        console.log(`📍 API URL: ${config.API_URL}`);
        console.log(`🖥️  Client URL: ${config.CLIENT_URL}`);
        
        return true;
        
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        return false;
    }
}

// ========== PUBLIC HTML ROUTES ==========

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'Public', 'login.html'));
});

app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'Public', 'login.html'));
});

// ========== PUBLIC API ROUTES ==========

// Health check endpoint with detailed status
app.get('/api/health', async (req, res) => {
    try {
        const startTime = Date.now();
        
        // Test database connection
        const { error: dbTest } = await supabase
            .from('users')
            .select('count', { count: 'exact', head: true });
        
        const dbLatency = Date.now() - startTime;
        
        // Get counts
        const [personsCount, seizuresCount, usersCount] = await Promise.all([
            supabase.from('persons').select('*', { count: 'exact', head: true }),
            supabase.from('seizures').select('*', { count: 'exact', head: true }),
            supabase.from('users').select('*', { count: 'exact', head: true })
        ]);
        
        res.json({
            success: true,
            message: 'SeizeTrack API is running',
            environment: config.NODE_ENV,
            database: {
                status: dbTest ? 'error' : 'connected',
                type: 'Supabase',
                latency: `${dbLatency}ms`
            },
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            counts: {
                persons: personsCount.count || 0,
                seizures: seizuresCount.count || 0,
                users: usersCount.count || 0
            }
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Service unhealthy',
            error: config.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Login endpoint with enhanced security
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Validate input
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }
        
        // Sanitize email
        const sanitizedEmail = email.toLowerCase().trim();
        
        // Find user by email
        const { data: users, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', sanitizedEmail);
        
        if (error) {
            console.error('Database error:', error);
            return res.status(500).json({
                success: false,
                message: 'Login service unavailable'
            });
        }
        
        if (!users || users.length === 0) {
            // Use same message for security (don't reveal if email exists)
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }
        
        const user = users[0];
        
        // Verify password with timing-safe comparison
        const isValidPassword = await bcrypt.compare(password, user.password);
        
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }
        
        // Create JWT token with limited payload
        const token = jwt.sign(
            {
                userId: user.id,
                email: user.email,
                role: user.role
            },
            config.JWT_SECRET,
            { 
                expiresIn: config.JWT_EXPIRES_IN,
                issuer: 'seizetrack-api',
                audience: 'seizetrack-client'
            }
        );
        
        // Log successful login (without sensitive data)
        console.log(`✅ User logged in: ${user.email} (${user.role})`);
        
        res.json({
            success: true,
            token: token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role,
                department: user.department
            },
            message: `Welcome back, ${user.name}!`
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred during login'
        });
    }
});

// Check session endpoint
app.get('/api/auth/check', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'No token provided'
            });
        }
        
        // Verify token
        const decoded = jwt.verify(token, config.JWT_SECRET, {
            issuer: 'seizetrack-api',
            audience: 'seizetrack-client'
        });
        
        // Get user from database (select only needed fields)
        const { data: users, error } = await supabase
            .from('users')
            .select('id, name, email, role, department')
            .eq('id', decoded.userId);
        
        if (error) throw error;
        
        if (!users || users.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        const user = users[0];
        
        res.json({
            success: true,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role,
                department: user.department
            }
        });
        
    } catch (error) {
        if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
            return res.status(403).json({
                success: false,
                message: error.name === 'TokenExpiredError' 
                    ? 'Session expired' 
                    : 'Invalid session'
            });
        }
        
        console.error('Check session error:', error);
        res.status(500).json({
            success: false,
            message: 'Session check failed'
        });
    }
});

// ========== PROTECTED ROUTES ==========

// Apply authentication middleware to all /api routes except public ones
app.use('/api', (req, res, next) => {
    const publicApiRoutes = ['/api/auth/login', '/api/health', '/api/auth/check'];
    if (publicApiRoutes.includes(req.path)) {
        return next();
    }
    authenticateToken(req, res, next);
});

// ========== PROTECTED HTML ROUTES ==========

app.get('/index.html', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'index.html'));
});

app.get('/AddSeizure.html', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'AddSeizure.html'));
});

app.get('/History.html', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'History.html'));
});

app.get('/Person.html', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'Person.html'));
});

// ========== PROTECTED API ROUTES ==========

// Logout endpoint
app.post('/api/auth/logout', (req, res) => {
    res.json({
        success: true,
        message: 'Logged out successfully'
    });
});

// Dashboard stats endpoint with caching
app.get('/api/stats/dashboard', async (req, res) => {
    try {
        // Set cache control
        res.set('Cache-Control', 'public, max-age=60'); // Cache for 1 minute
        
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        // Run queries in parallel for better performance
        const [
            totalSeizuresResult,
            todaySeizuresResult,
            totalPersonsResult,
            repeatOffendersResult,
            recentSeizuresResult
        ] = await Promise.all([
            supabase.from('seizures').select('*', { count: 'exact', head: true }),
            supabase.from('seizures').select('*', { count: 'exact', head: true })
                .gte('created_at', today.toISOString()),
            supabase.from('persons').select('*', { count: 'exact', head: true }),
            supabase.from('persons').select('*', { count: 'exact', head: true })
                .gte('total_seizures', 2),
            supabase.from('seizures')
                .select(`
                    id,
                    created_at,
                    phone_model,
                    location,
                    seized_by,
                    status,
                    persons (
                        name,
                        matric_number,
                        department
                    )
                `)
                .order('created_at', { ascending: false })
                .limit(5)
        ]);
        
        res.json({
            success: true,
            data: {
                stats: {
                    totalSeizures: totalSeizuresResult.count || 0,
                    todaySeizures: todaySeizuresResult.count || 0,
                    totalPersons: totalPersonsResult.count || 0,
                    repeatOffenders: repeatOffendersResult.count || 0
                },
                recentSeizures: (recentSeizuresResult.data || []).map(row => ({
                    id: row.id,
                    createdAt: row.created_at,
                    person: row.persons ? {
                        name: row.persons.name,
                        matricNumber: row.persons.matric_number
                    } : null,
                    phoneModel: row.phone_model,
                    location: row.location,
                    seizedBy: row.seized_by,
                    status: row.status
                }))
            }
        });
        
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch dashboard data'
        });
    }
});

// CRUD Operations for Persons
app.get('/api/persons', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('persons')
            .select('*')
            .order('name');
        
        if (error) throw error;
        
        res.json({
            success: true,
            data: data
        });
        
    } catch (error) {
        console.error('Get persons error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch persons'
        });
    }
});

app.get('/api/persons/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        const { data, error } = await supabase
            .from('persons')
            .select('*')
            .eq('id', id)
            .single();
        
        if (error) throw error;
        
        if (!data) {
            return res.status(404).json({
                success: false,
                message: 'Person not found'
            });
        }
        
        res.json({
            success: true,
            data: data
        });
        
    } catch (error) {
        console.error('Get person error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch person'
        });
    }
});

app.post('/api/persons', async (req, res) => {
    try {
        const { name, matric_number, department, level } = req.body;
        
        // Validate required fields
        if (!name || !matric_number) {
            return res.status(400).json({
                success: false,
                message: 'Name and matric number are required'
            });
        }
        
        const { data, error } = await supabase
            .from('persons')
            .insert([
                {
                    name,
                    matric_number: matric_number.toUpperCase(),
                    department,
                    level,
                    total_seizures: 0
                }
            ])
            .select();
        
        if (error) {
            if (error.code === '23505') { // Unique violation
                return res.status(409).json({
                    success: false,
                    message: 'Matric number already exists'
                });
            }
            throw error;
        }
        
        res.json({
            success: true,
            message: 'Person added successfully',
            data: data[0]
        });
        
    } catch (error) {
        console.error('Create person error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to add person'
        });
    }
});

app.put('/api/persons/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;
        
        // Remove fields that shouldn't be updated
        delete updates.id;
        delete updates.created_at;
        delete updates.total_seizures;
        
        const { data, error } = await supabase
            .from('persons')
            .update(updates)
            .eq('id', id)
            .select();
        
        if (error) throw error;
        
        if (!data || data.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Person not found'
            });
        }
        
        res.json({
            success: true,
            message: 'Person updated successfully',
            data: data[0]
        });
        
    } catch (error) {
        console.error('Update person error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update person'
        });
    }
});

app.delete('/api/persons/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        // Check if person has seizures
        const { count } = await supabase
            .from('seizures')
            .select('*', { count: 'exact', head: true })
            .eq('person_id', id);
        
        if (count && count > 0) {
            return res.status(409).json({
                success: false,
                message: 'Cannot delete person with existing seizures'
            });
        }
        
        const { error } = await supabase
            .from('persons')
            .delete()
            .eq('id', id);
        
        if (error) throw error;
        
        res.json({
            success: true,
            message: 'Person deleted successfully'
        });
        
    } catch (error) {
        console.error('Delete person error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete person'
        });
    }
});

// CRUD Operations for Seizures
app.get('/api/seizures', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('seizures')
            .select(`
                *,
                persons (
                    name,
                    matric_number,
                    department
                )
            `)
            .order('created_at', { ascending: false });
        
        if (error) throw error;
        
        res.json({
            success: true,
            data: data
        });
        
    } catch (error) {
        console.error('Get seizures error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch seizures'
        });
    }
});

app.get('/api/seizures/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        const { data, error } = await supabase
            .from('seizures')
            .select(`
                *,
                persons (
                    name,
                    matric_number,
                    department,
                    level
                )
            `)
            .eq('id', id)
            .single();
        
        if (error) throw error;
        
        if (!data) {
            return res.status(404).json({
                success: false,
                message: 'Seizure not found'
            });
        }
        
        res.json({
            success: true,
            data: data
        });
        
    } catch (error) {
        console.error('Get seizure error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch seizure'
        });
    }
});

app.post('/api/seizures', async (req, res) => {
    try {
        const {
            person_id,
            phone_model,
            device_color,
            location,
            seized_by,
            seizure_reason,
            notes,
            status
        } = req.body;
        
        // Validate required fields
        if (!person_id || !phone_model || !location || !seized_by) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields'
            });
        }
        
        // Verify person exists
        const { data: person, error: personCheckError } = await supabase
            .from('persons')
            .select('id, total_seizures')
            .eq('id', person_id)
            .single();
        
        if (personCheckError || !person) {
            return res.status(404).json({
                success: false,
                message: 'Person not found'
            });
        }
        
        // Insert seizure
        const { data: seizure, error: seizureError } = await supabase
            .from('seizures')
            .insert([
                {
                    person_id,
                    phone_model,
                    device_color,
                    location,
                    seized_by,
                    seizure_reason,
                    notes,
                    status: status || 'active'
                }
            ])
            .select();
        
        if (seizureError) throw seizureError;
        
        // Update person's seizure count
        await supabase
            .from('persons')
            .update({
                total_seizures: (person.total_seizures || 0) + 1,
                last_seized: new Date().toISOString()
            })
            .eq('id', person_id);
        
        res.json({
            success: true,
            message: 'Seizure recorded successfully',
            data: seizure[0]
        });
        
    } catch (error) {
        console.error('Create seizure error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to record seizure'
        });
    }
});

app.put('/api/seizures/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;
        
        // Remove fields that shouldn't be updated
        delete updates.id;
        delete updates.created_at;
        delete updates.person_id; // Don't allow changing person
        
        const { data, error } = await supabase
            .from('seizures')
            .update(updates)
            .eq('id', id)
            .select();
        
        if (error) throw error;
        
        if (!data || data.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Seizure not found'
            });
        }
        
        res.json({
            success: true,
            message: 'Seizure updated successfully',
            data: data[0]
        });
        
    } catch (error) {
        console.error('Update seizure error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update seizure'
        });
    }
});

app.delete('/api/seizures/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        const { error } = await supabase
            .from('seizures')
            .delete()
            .eq('id', id);
        
        if (error) throw error;
        
        res.json({
            success: true,
            message: 'Seizure deleted successfully'
        });
        
    } catch (error) {
        console.error('Delete seizure error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete seizure'
        });
    }
});

// ========== ERROR HANDLERS ==========

// 404 handler
app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
        res.status(404).json({
            success: false,
            message: 'API endpoint not found'
        });
    } else {
        res.status(404).sendFile(path.join(__dirname, 'Public', '404.html'));
    }
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    
    const statusCode = err.statusCode || 500;
    const message = config.NODE_ENV === 'production' 
        ? 'Internal server error' 
        : err.message;
    
    if (req.path.startsWith('/api/')) {
        res.status(statusCode).json({
            success: false,
            message: message,
            ...(config.NODE_ENV === 'development' && { stack: err.stack })
        });
    } else {
        res.status(statusCode).send('Internal server error');
    }
});

// ========== SERVER STARTUP ==========
async function startServer() {
    try {
        console.log('🚀 Starting SeizeTrack Server...\n');
        console.log('='.repeat(60));
        console.log('📋 PRODUCTION CONFIGURATION');
        console.log('='.repeat(60));
        console.log(`🌍 Environment: ${config.NODE_ENV}`);
        console.log(`📍 Port: ${config.PORT}`);
        console.log(`🖥️  API URL: ${config.API_URL}`);
        console.log(`🔗 Client URL: ${config.CLIENT_URL}`);
        console.log(`⏱️  Rate Limit: ${config.RATE_LIMIT_MAX} requests per ${config.RATE_LIMIT_WINDOW/60000} minutes`);
        console.log('='.repeat(60));
        
        // Initialize database connection
        const dbConnected = await initializeDatabase();
        
        if (!dbConnected) {
            console.warn('\n⚠️  Warning: Database connection failed. Server will start but some features may not work.');
        }
        
        // Start server
        const server = app.listen(config.PORT, () => {
            console.log('\n' + '='.repeat(60));
            console.log('✅ SEIZETRACK SERVER IS RUNNING');
            console.log('='.repeat(60));
            console.log(`📡 API: ${config.API_URL}`);
            console.log(`💾 Database: ${dbConnected ? 'Connected' : 'Disconnected'}`);
            console.log(`🚦 Status: Ready to accept connections`);
            console.log('='.repeat(60));
        });
        
        // Graceful shutdown
        const gracefulShutdown = async () => {
            console.log('\n\n🛑 Shutting down gracefully...');
            server.close(() => {
                console.log('👋 Server closed');
                process.exit(0);
            });
            
            // Force close after 10 seconds
            setTimeout(() => {
                console.error('⚠️ Forcefully shutting down');
                process.exit(1);
            }, 10000);
        };
        
        process.on('SIGTERM', gracefulShutdown);
        process.on('SIGINT', gracefulShutdown);
        
    } catch (error) {
        console.error('❌ Failed to start server:', error.message);
        process.exit(1);
    }
}

// Start server if not in test mode
if (require.main === module) {
    startServer();
}

// Export for testing
module.exports = app;