require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// =============================================
// SEIZETRACK API SERVER WITH SUPABASE - PRODUCTION
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
    CLIENT_URL: process.env.CLIENT_URL || 'https://biulegacycampus.vercel.app', // Your Vercel frontend
    API_URL: process.env.API_URL || 'https://biu-legacycampus.onrender.com', // Your Render backend
    RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
    RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX) || 100
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
            connectSrc: ["'self'", config.API_URL, config.CLIENT_URL, config.SUPABASE_URL]
        }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Compression
app.use(compression());

// Rate limiting - only apply to API routes
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
app.use('/api/', limiter);

// CORS configuration for production - Allow Vercel frontend
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            config.CLIENT_URL,
            'https://biulegacycampus.vercel.app',
            'http://localhost:3000',
            'http://localhost:5000'
        ].filter(Boolean);
        
        // Allow requests with no origin (like mobile apps or curl)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1 || config.NODE_ENV !== 'production') {
            callback(null, true);
        } else {
            console.log('CORS blocked origin:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Trust proxy (for Render)
app.set('trust proxy', 1);

// Request logging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - Origin: ${req.get('origin') || 'unknown'}`);
    next();
});

// ========== AUTHENTICATION MIDDLEWARE ==========

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access token required. Please login.'
        });
    }

    jwt.verify(token, config.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({
                success: false,
                message: err.name === 'TokenExpiredError' 
                    ? 'Token has expired' 
                    : 'Invalid token'
            });
        }
        req.user = user;
        next();
    });
};

// ========== DATABASE CONNECTION ==========

async function checkDatabaseConnection() {
    try {
        console.log('\n🔍 Connecting to Supabase...');
        
        const { error } = await supabase
            .from('users')
            .select('count', { count: 'exact', head: true });
        
        if (error) {
            console.error('❌ Supabase connection failed:', error.message);
            return false;
        }
        
        console.log('✅ Connected to Supabase successfully!');
        console.log(`🌍 Environment: ${config.NODE_ENV}`);
        console.log(`📍 API URL: ${config.API_URL}`);
        console.log(`🖥️  Client URL: ${config.CLIENT_URL}`);
        
        return true;
        
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        return false;
    }
}

// ========== PUBLIC API ROUTES ==========

// Health check endpoint
app.get('/api/health', async (req, res) => {
    try {
        const startTime = Date.now();
        
        const { error: dbTest } = await supabase
            .from('users')
            .select('count', { count: 'exact', head: true });
        
        const dbLatency = Date.now() - startTime;
        
        res.json({
            success: true,
            message: 'SeizeTrack API is running',
            environment: config.NODE_ENV,
            database: {
                status: dbTest ? 'error' : 'connected',
                latency: `${dbLatency}ms`
            },
            timestamp: new Date().toISOString(),
            uptime: process.uptime()
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Service unhealthy'
        });
    }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }
        
        const sanitizedEmail = email.toLowerCase().trim();
        
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
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }
        
        const user = users[0];
        const isValidPassword = await bcrypt.compare(password, user.password);
        
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }
        
        const token = jwt.sign(
            {
                userId: user.id,
                email: user.email,
                role: user.role
            },
            config.JWT_SECRET,
            { 
                expiresIn: config.JWT_EXPIRES_IN
            }
        );
        
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
        
        const decoded = jwt.verify(token, config.JWT_SECRET);
        
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

// Logout endpoint
app.post('/api/auth/logout', (req, res) => {
    res.json({
        success: true,
        message: 'Logged out successfully'
    });
});

// ========== PROTECTED API ROUTES ==========
// All routes below this middleware require authentication
app.use('/api', authenticateToken);

// Dashboard stats endpoint
app.get('/api/stats/dashboard', async (req, res) => {
    try {
        res.set('Cache-Control', 'public, max-age=60');
        
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
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
            if (error.code === '23505') {
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
        
        if (!person_id || !phone_model || !location || !seized_by) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields'
            });
        }
        
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
        
        delete updates.id;
        delete updates.created_at;
        delete updates.person_id;
        
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

// 404 handler for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'API endpoint not found'
    });
});

// Root route - return API info
app.get('/', (req, res) => {
    res.json({
        name: 'SeizeTrack API',
        version: '1.0.0',
        status: 'running',
        endpoints: {
            health: '/api/health',
            login: '/api/auth/login',
            check: '/api/auth/check',
            dashboard: '/api/stats/dashboard',
            persons: '/api/persons',
            seizures: '/api/seizures'
        },
        frontend: config.CLIENT_URL,
        documentation: 'This is an API server. Please use the frontend at ' + config.CLIENT_URL
    });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    
    res.status(500).json({
        success: false,
        message: 'Internal server error'
    });
});

// ========== SERVER STARTUP ==========
async function startServer() {
    try {
        console.log('🚀 Starting SeizeTrack API Server...\n');
        console.log('='.repeat(60));
        console.log('📋 PRODUCTION CONFIGURATION');
        console.log('='.repeat(60));
        console.log(`🌍 Environment: ${config.NODE_ENV}`);
        console.log(`📍 Port: ${config.PORT}`);
        console.log(`🖥️  API URL: ${config.API_URL}`);
        console.log(`🔗 Client URL: ${config.CLIENT_URL}`);
        console.log('='.repeat(60));
        
        const dbConnected = await checkDatabaseConnection();
        
        const server = app.listen(config.PORT, () => {
            console.log('\n' + '='.repeat(60));
            console.log('✅ SEIZETRACK API SERVER IS RUNNING');
            console.log('='.repeat(60));
            console.log(`📡 API: ${config.API_URL}`);
            console.log(`💾 Database: ${dbConnected ? 'Connected' : 'Disconnected'}`);
            console.log(`🚦 Status: Ready to accept API requests`);
            console.log('='.repeat(60));
            console.log('\n📝 This server only handles API requests.');
            console.log(`🌐 Frontend is served by Vercel at: ${config.CLIENT_URL}`);
            console.log('='.repeat(60));
        });
        
        const gracefulShutdown = async () => {
            console.log('\n\n🛑 Shutting down gracefully...');
            server.close(() => {
                console.log('👋 Server closed');
                process.exit(0);
            });
            
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

// Start the server
startServer();

// Export for testing
module.exports = app;