require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// =============================================
// SEIZETRACK SERVER WITH POSTGRESQL
// =============================================

// Configuration
const config = {
    PORT: process.env.PORT || 5000,
    DB_USER: process.env.DB_USER || 'postgres',
    DB_HOST: process.env.DB_HOST || 'localhost',
    DB_NAME: process.env.DB_NAME || 'seizetrack',
    DB_PASSWORD: process.env.DB_PASSWORD || '',
    DB_PORT: process.env.DB_PORT || 5432,
    JWT_SECRET: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production',
    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '24h'
};

// Create Express app
const app = express();

// PostgreSQL connection pool
const pool = new Pool({
    user: config.DB_USER,
    host: config.DB_HOST,
    database: config.DB_NAME,
    password: config.DB_PASSWORD,
    port: config.DB_PORT,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

// ========== MIDDLEWARE SETUP ==========

// CORS middleware
app.use(cors({
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from public folder
app.use(express.static('public'));

// ========== AUTHENTICATION MIDDLEWARE ==========

const authenticateToken = (req, res, next) => {
    // Skip authentication for public routes
    if (req.path === '/api/auth/login' || 
        req.path === '/api/health' || 
        req.path === '/' || 
        req.path === '/login.html' ||
        req.path === '/api/auth/check') {
        return next();
    }

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        // For API requests, return JSON error
        if (req.path.startsWith('/api/')) {
            return res.status(401).json({
                success: false,
                message: 'Access token required. Please login.'
            });
        }
        // For HTML requests, redirect to login
        return res.redirect('/');
    }

    // Verify JWT token
    jwt.verify(token, config.JWT_SECRET, (err, user) => {
        if (err) {
            if (req.path.startsWith('/api/')) {
                return res.status(403).json({
                    success: false,
                    message: 'Invalid or expired token'
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
        console.log('\n🔍 Connecting to PostgreSQL database...');
        
        const client = await pool.connect();
        
        // Check if tables exist, create them if not
        await createTablesIfNotExist(client);
        
        client.release();
        
        console.log('✅ Connected to PostgreSQL database successfully!');
        return true;
        
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        console.log('\n💡 Troubleshooting tips:');
        console.log('   1. Make sure PostgreSQL is running');
        console.log('   2. Check your database credentials in .env file');
        console.log('   3. Create the database first: CREATE DATABASE seizetrack;');
        return false;
    }
}

async function createTablesIfNotExist(client) {
    console.log('📊 Checking/Creating database tables...');
    
    // Users table - using 'password' column (not password_hash)
    await client.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'security',
            department VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    // Persons table
    await client.query(`
        CREATE TABLE IF NOT EXISTS persons (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            matric_number VARCHAR(50) UNIQUE NOT NULL,
            department VARCHAR(255),
            level VARCHAR(50),
            total_seizures INTEGER DEFAULT 0,
            last_seized TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    // Seizures table
    await client.query(`
        CREATE TABLE IF NOT EXISTS seizures (
            id SERIAL PRIMARY KEY,
            person_id INTEGER REFERENCES persons(id) ON DELETE CASCADE,
            phone_model VARCHAR(255) NOT NULL,
            device_color VARCHAR(100),
            location VARCHAR(255) NOT NULL,
            seized_by VARCHAR(255) NOT NULL,
            seizure_reason TEXT,
            notes TEXT,
            status VARCHAR(50) DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    // Create indexes for better performance
    await client.query(`CREATE INDEX IF NOT EXISTS idx_persons_matric ON persons(matric_number)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_seizures_person_id ON seizures(person_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_seizures_created_at ON seizures(created_at)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_seizures_status ON seizures(status)`);
    
    // Check if any user exists
    const checkUsers = await client.query(
        "SELECT COUNT(*) as count FROM users"
    );
    
    const userCount = parseInt(checkUsers.rows[0].count);
    
    if (userCount === 0) {
        console.log('👤 No users found, creating admin user...');
        
        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash('admin123', salt);
        
        // Create admin user - using 'password' column
        await client.query(`
            INSERT INTO users (name, email, password, role, department)
            VALUES ($1, $2, $3, $4, $5)
        `, [
            'Admin User',
            'admin@seizetrack.com',
            hashedPassword,
            'admin',
            'Security Dept'
        ]);
        
        console.log('✅ Created default admin user: admin@seizetrack.com / admin123');
    } else {
        console.log(`✅ Found ${userCount} existing user(s)`);
    }
    
    console.log('✅ Database tables are ready');
}

// ========== PUBLIC HTML ROUTES ==========

// Serve login page as default
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve login.html
app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ========== PUBLIC API ROUTES ==========

// Health check endpoint
app.get('/api/health', async (req, res) => {
    try {
        // Test database connection
        const dbCheck = await pool.query('SELECT NOW() as time');
        
        // Get counts
        const personsCount = await pool.query('SELECT COUNT(*) as count FROM persons');
        const seizuresCount = await pool.query('SELECT COUNT(*) as count FROM seizures');
        const usersCount = await pool.query('SELECT COUNT(*) as count FROM users');
        
        res.json({
            success: true,
            message: 'SeizeTrack API with PostgreSQL is running',
            database: 'PostgreSQL',
            timestamp: new Date().toISOString(),
            dbTime: dbCheck.rows[0].time,
            counts: {
                persons: parseInt(personsCount.rows[0].count),
                seizures: parseInt(seizuresCount.rows[0].count),
                users: parseInt(usersCount.rows[0].count)
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Database connection error',
            error: error.message
        });
    }
});

// Login endpoint - SIMPLIFIED VERSION
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
        
        // Find user by email
        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email.toLowerCase().trim()]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }
        
        const user = result.rows[0];
        
        // Verify password - using 'password' column
        const isValidPassword = await bcrypt.compare(password, user.password);
        
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }
        
        // Create JWT token
        const token = jwt.sign(
            {
                userId: user.id,
                email: user.email,
                role: user.role,
                name: user.name
            },
            config.JWT_SECRET,
            { expiresIn: config.JWT_EXPIRES_IN }
        );
        
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
            message: 'Server error',
            error: error.message
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
        const decoded = jwt.verify(token, config.JWT_SECRET);
        
        // Get user from database
        const result = await pool.query(
            'SELECT id, name, email, role, department FROM users WHERE id = $1',
            [decoded.userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        const user = result.rows[0];
        
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
        if (error.name === 'JsonWebTokenError') {
            return res.status(403).json({
                success: false,
                message: 'Invalid token'
            });
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(403).json({
                success: false,
                message: 'Token expired'
            });
        }
        
        console.error('Check session error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// ========== PROTECTED ROUTES ==========

// Apply authentication middleware
app.use('/api', authenticateToken);

// ========== PROTECTED HTML ROUTES ==========

app.get('/index.html', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/AddSeizure.html', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'AddSeizure.html'));
});

app.get('/History.html', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'History.html'));
});

app.get('/Person.html', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'Person.html'));
});

// ========== PROTECTED API ROUTES ==========

// Logout endpoint
app.post('/api/auth/logout', (req, res) => {
    res.json({
        success: true,
        message: 'Logged out successfully'
    });
});

// Dashboard stats endpoint
app.get('/api/stats/dashboard', async (req, res) => {
    try {
        // Get total seizures
        const totalSeizuresResult = await pool.query(
            'SELECT COUNT(*) as count FROM seizures'
        );
        
        // Get today's seizures
        const todaySeizuresResult = await pool.query(`
            SELECT COUNT(*) as count FROM seizures 
            WHERE DATE(created_at) = CURRENT_DATE
        `);
        
        // Get total persons
        const totalPersonsResult = await pool.query(
            'SELECT COUNT(*) as count FROM persons'
        );
        
        // Get repeat offenders (persons with 2+ seizures)
        const repeatOffendersResult = await pool.query(`
            SELECT COUNT(*) as count FROM persons 
            WHERE total_seizures >= 2
        `);
        
        // Get recent seizures (last 5)
        const recentSeizuresResult = await pool.query(`
            SELECT 
                s.*,
                p.name,
                p.matric_number,
                p.department
            FROM seizures s
            JOIN persons p ON s.person_id = p.id
            ORDER BY s.created_at DESC
            LIMIT 5
        `);
        
        res.json({
            success: true,
            data: {
                stats: {
                    totalSeizures: parseInt(totalSeizuresResult.rows[0].count),
                    todaySeizures: parseInt(todaySeizuresResult.rows[0].count),
                    totalPersons: parseInt(totalPersonsResult.rows[0].count),
                    repeatOffenders: parseInt(repeatOffendersResult.rows[0].count)
                },
                recentSeizures: recentSeizuresResult.rows.map(row => ({
                    id: row.id,
                    createdAt: row.created_at,
                    person: {
                        name: row.name,
                        matricNumber: row.matric_number
                    },
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
            message: 'Server error',
            error: error.message
        });
    }
});

// ========== 404 HANDLER ==========
app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({
            success: false,
            message: 'Endpoint not found'
        });
    }
    res.status(404).send('Page not found');
});

// ========== ERROR HANDLER ==========
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    
    if (req.path.startsWith('/api/')) {
        return res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: err.message
        });
    }
    
    res.status(500).send('Internal server error');
});

// ========== SERVER STARTUP ==========
async function startServer() {
    try {
        console.log('🚀 Starting SeizeTrack Server with PostgreSQL...\n');
        
        // Initialize database
        const dbConnected = await initializeDatabase();
        
        app.listen(config.PORT, () => {
            console.log('\n' + '='.repeat(60));
            console.log('🚀 SEIZETRACK SERVER STARTED');
            console.log('='.repeat(60));
            console.log(`📍 Server: http://localhost:${config.PORT}`);
            console.log(`📊 Database: ${dbConnected ? 'Connected' : 'Not Connected'}`);
            console.log(`🔐 Default Login: admin@seizetrack.com / admin123`);
            console.log('   ⚠️  Change password after first login!');
            console.log('\n📚 Available Pages:');
            console.log(`   Login:       http://localhost:${config.PORT}`);
            console.log(`   Dashboard:   http://localhost:${config.PORT}/index.html`);
            console.log(`   Add Seizure: http://localhost:${config.PORT}/AddSeizure.html`);
            console.log(`   History:     http://localhost:${config.PORT}/History.html`);
            console.log(`   Persons:     http://localhost:${config.PORT}/Person.html`);
            console.log('\n📚 API Endpoints:');
            console.log(`   GET  http://localhost:${config.PORT}/api/health`);
            console.log(`   POST http://localhost:${config.PORT}/api/auth/login`);
            console.log(`   GET  http://localhost:${config.PORT}/api/auth/check`);
            console.log('='.repeat(60));
        });
        
    } catch (error) {
        console.error('❌ Failed to start server:', error.message);
        process.exit(1);
    }
}

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n💾 Closing database connections...');
    await pool.end();
    console.log('👋 Server shut down');
    process.exit(0);
});

// Start server
startServer();