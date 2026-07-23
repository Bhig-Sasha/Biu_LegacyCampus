require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcrypt");

// =============================================
// SEIZETRACK API SERVER - PRODUCTION
// =============================================

// Configuration
const requiredEnvVars = ['SUPABASE_URL', 'SUPABASE_ANON_KEY'];
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
    JWT_SECRET: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production',
    NODE_ENV: process.env.NODE_ENV || 'production',
    CLIENT_URL: process.env.CLIENT_URL || 'https://biulegacycampus.vercel.app',
    API_URL: process.env.API_URL || 'https://biu-legacycampus.onrender.com',
    RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
    RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX) || 100,
    BCRYPT_ROUNDS: parseInt(process.env.BCRYPT_ROUNDS) || 10
};

const app = express();

// Initialize Supabase
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

// ========== MIDDLEWARE ==========

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

app.use(compression());

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

const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            config.CLIENT_URL,
            'https://biulegacycampus.vercel.app',
            'http://localhost:3000',
            'http://localhost:5000',
            'http://127.0.0.1:3000',
            'http://127.0.0.1:5000'
        ].filter(Boolean);
        
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1 || config.NODE_ENV !== 'production') {
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
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.set('trust proxy', 1);

// ========== AUTHENTICATION UTILITIES ==========

function generateToken(user) {
    const payload = {
        id: user.id,
        email: user.email,
        role: user.role,
        timestamp: Date.now()
    };
    return Buffer.from(JSON.stringify(payload)).toString('base64');
}

function verifyToken(token) {
    try {
        const decoded = JSON.parse(Buffer.from(token, 'base64').toString());
        if (Date.now() - decoded.timestamp > 24 * 60 * 60 * 1000) {
            return null;
        }
        return decoded;
    } catch (error) {
        return null;
    }
}

async function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            success: false,
            message: 'No token provided'
        });
    }

    const token = authHeader.split(' ')[1];
    const decoded = verifyToken(token);
    
    if (!decoded) {
        return res.status(401).json({
            success: false,
            message: 'Invalid or expired token'
        });
    }

    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('id, email, name, role, department')
            .eq('id', decoded.id)
            .single();

        if (error || !user) {
            return res.status(401).json({
                success: false,
                message: 'User not found'
            });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: 'Authentication failed'
        });
    }
}

function authorize(...roles) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Not authenticated'
            });
        }

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                message: 'Insufficient permissions'
            });
        }

        next();
    };
}

// ========== AUTHENTICATION ROUTES ==========

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }

        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email.toLowerCase())
            .single();

        if (error || !user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        const token = generateToken(user);
        delete user.password;

        await supabase
            .from('users')
            .update({ updated_at: new Date().toISOString() })
            .eq('id', user.id);

        res.json({
            success: true,
            message: 'Login successful',
            token: token,
            user: user
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed'
        });
    }
});

app.post('/api/check', authenticate, async (req, res) => {
    res.json({
        success: true,
        user: req.user
    });
});

app.post('/api/logout', authenticate, async (req, res) => {
    res.json({
        success: true,
        message: 'Logged out successfully'
    });
});

app.post('/api/register', authenticate, authorize('admin'), async (req, res) => {
    try {
        const { email, password, name, role, department } = req.body;
        
        if (!email || !password || !name) {
            return res.status(400).json({
                success: false,
                message: 'Email, password, and name are required'
            });
        }

        const hashedPassword = await bcrypt.hash(password, config.BCRYPT_ROUNDS);
        
        const { data, error } = await supabase
            .from('users')
            .insert([{
                email: email.toLowerCase(),
                password: hashedPassword,
                name,
                role: role || 'student',
                department: department || null
            }])
            .select('id, email, name, role, department');

        if (error) {
            if (error.code === '23505') {
                return res.status(409).json({
                    success: false,
                    message: 'Email already exists'
                });
            }
            throw error;
        }

        res.json({
            success: true,
            message: 'User created successfully',
            user: data[0]
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Registration failed'
        });
    }
});

app.get('/api/profile', authenticate, async (req, res) => {
    res.json({
        success: true,
        user: req.user
    });
});

// ========== API ROUTES ==========

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

app.get('/api/stats/dashboard', authenticate, async (req, res) => {
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

// ========== PERSONS CRUD ==========

app.get('/api/persons', authenticate, async (req, res) => {
    try {
        const { search } = req.query;
        
        let query = supabase.from('persons').select('*');
        
        if (search) {
            query = query.or(`name.ilike.%${search}%,matric_number.ilike.%${search}%,department.ilike.%${search}%`);
        }
        
        const { data, error } = await query.order('name');
        
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

app.get('/api/persons/:id', authenticate, async (req, res) => {
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

app.post('/api/persons', authenticate, authorize('admin', 'security'), async (req, res) => {
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

app.put('/api/persons/:id', authenticate, authorize('admin', 'security'), async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;
        
        delete updates.id;
        delete updates.created_at;
        delete updates.total_seizures;
        delete updates.last_seized;
        
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

app.delete('/api/persons/:id', authenticate, authorize('admin'), async (req, res) => {
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

// ========== SEIZURES CRUD ==========

app.get('/api/seizures', authenticate, async (req, res) => {
    try {
        const { person_id } = req.query;
        
        let query = supabase
            .from('seizures')
            .select(`
                *,
                persons (
                    name,
                    matric_number,
                    department,
                    level
                )
            `);
        
        if (person_id) {
            query = query.eq('person_id', person_id);
        }
        
        const { data, error } = await query.order('created_at', { ascending: false });
        
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

app.get('/api/seizures/:id', authenticate, async (req, res) => {
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

app.post('/api/seizures', authenticate, authorize('admin', 'security'), async (req, res) => {
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
        
        if (!person_id || !phone_model || !location) {
            return res.status(400).json({
                success: false,
                message: 'Person ID, phone model, and location are required'
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
                    seized_by: seized_by || req.user.name,
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

app.put('/api/seizures/:id', authenticate, authorize('admin', 'security'), async (req, res) => {
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

app.delete('/api/seizures/:id', authenticate, authorize('admin'), async (req, res) => {
    try {
        const { id } = req.params;
        
        const { data: seizure, error: getError } = await supabase
            .from('seizures')
            .select('person_id')
            .eq('id', id)
            .single();
        
        if (getError || !seizure) {
            return res.status(404).json({
                success: false,
                message: 'Seizure not found'
            });
        }
        
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

// ========== ADMIN ROUTES ==========

app.get('/api/users', authenticate, authorize('admin'), async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('id, email, name, role, department, created_at, updated_at')
            .order('created_at', { ascending: false });
        
        if (error) throw error;
        
        res.json({
            success: true,
            data: data
        });
        
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch users'
        });
    }
});

app.put('/api/users/:id/role', authenticate, authorize('admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const { role } = req.body;
        
        if (!role || !['admin', 'security', 'student'].includes(role)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid role'
            });
        }
        
        const { data, error } = await supabase
            .from('users')
            .update({ role })
            .eq('id', id)
            .select('id, email, name, role');
        
        if (error) throw error;
        
        if (!data || data.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        res.json({
            success: true,
            message: 'User role updated successfully',
            user: data[0]
        });
        
    } catch (error) {
        console.error('Update user role error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user role'
        });
    }
});

// ========== ERROR HANDLERS ==========

app.use('/api/*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'API endpoint not found'
    });
});

app.get('/', (req, res) => {
    res.json({
        name: 'SeizeTrack API',
        version: '2.0.0',
        status: 'running'
    });
});

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
        console.log(`🌍 Environment: ${config.NODE_ENV}`);
        console.log(`📍 Port: ${config.PORT}`);
        console.log(`🖥️  API URL: ${config.API_URL}`);
        
        // Check database connection
        const { error } = await supabase
            .from('users')
            .select('count', { count: 'exact', head: true });
        
        if (error) {
            console.error('❌ Database connection failed:', error.message);
            process.exit(1);
        }
        
        console.log('✅ Connected to Supabase successfully!');
        
        app.listen(config.PORT, () => {
            console.log(`🚀 Server running on port ${config.PORT}`);
        });
        
        // Graceful shutdown
        process.on('SIGTERM', () => {
            console.log('🛑 Shutting down...');
            process.exit(0);
        });
        
        process.on('SIGINT', () => {
            console.log('🛑 Shutting down...');
            process.exit(0);
        });
        
    } catch (error) {
        console.error('❌ Failed to start server:', error.message);
        process.exit(1);
    }
}

startServer();