require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { body, param, query, validationResult } = require("express-validator");

// =============================================
// SEIZETRACK API SERVER - PRODUCTION (HARDENED)
// =============================================

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
    CLIENT_URL: process.env.CLIENT_URL || 'https://biulegacycampus.netlify.app',
    API_URL: process.env.API_URL || 'https://biu-legacycampus.onrender.com',
    RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
    RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX) || 100,
    BCRYPT_ROUNDS: parseInt(process.env.BCRYPT_ROUNDS) || 12
};

const app = express();

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
    message: { success: false, message: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { success: false, message: 'Too many login attempts. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            'https://biulegacycampus.netlify.app',
            'https://biulegacycampus.vercel.app',
            'https://biu-legacycampus.onrender.com',
            'http://localhost:3000',
            'http://localhost:5000',
            'http://localhost:5500',
            'http://127.0.0.1:3000',
            'http://127.0.0.1:5000',
            'http://127.0.0.1:5500',
            'https://localhost:3000',
            'https://localhost:5000',
        ];

        if (config.CLIENT_URL) allowedOrigins.push(config.CLIENT_URL);
        if (!origin) return callback(null, true);

        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.log(`❌ CORS blocked request from: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
        'Content-Type', 'Authorization', 'X-Requested-With', 'Accept',
        'Origin', 'Access-Control-Request-Method', 'Access-Control-Request-Headers'
    ],
    exposedHeaders: ['Content-Length', 'X-Request-Id'],
    optionsSuccessStatus: 200,
    preflightContinue: false,
    maxAge: 86400
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.set('trust proxy', 1);

if (config.NODE_ENV !== 'production') {
    app.use((req, res, next) => {
        console.log(`${req.method} ${req.path} - Origin: ${req.headers.origin}`);
        next();
    });
}

// ========== AUTHENTICATION UTILITIES ==========

function generateToken(user) {
    return jwt.sign(
        { id: user.id, email: user.email, role: user.role },
        config.JWT_SECRET,
        { expiresIn: config.JWT_EXPIRES_IN }
    );
}

function verifyToken(token) {
    try {
        return jwt.verify(token, config.JWT_SECRET);
    } catch (err) {
        return null;
    }
}

function sanitizeUser(user) {
    if (!user) return null;
    const { password, ...safeUser } = user;
    return safeUser;
}

async function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, message: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = verifyToken(token);

    if (!decoded) {
        return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }

    try {
        const { data: user, error } = await supabase
            .from('users')
            .select(`
                id, email, name, role, department,
                surname, first_name, middle_name, date_of_birth,
                gender, marital_status, nationality, state_of_origin,
                lga, religion, phone, address,
                created_at, updated_at, profile_updated_at
            `)
            .eq('id', decoded.id)
            .single();

        if (error || !user) {
            return res.status(401).json({ success: false, message: 'User not found' });
        }

        if (user.role !== decoded.role) {
            return res.status(401).json({
                success: false,
                message: 'Token role mismatch – please log in again'
            });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Authentication failed' });
    }
}

function authorize(...roles) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ success: false, message: 'Not authenticated' });
        }
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ success: false, message: 'Insufficient permissions' });
        }
        next();
    };
}

function handleValidationErrors(req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            message: 'Validation failed',
            errors: errors.array().map(e => ({ field: e.path, message: e.msg }))
        });
    }
    next();
}

// ========== AUTHENTICATION ROUTES ==========

app.post('/api/login',
    loginLimiter,
    [
        body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
        body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
    ],
    handleValidationErrors,
    async (req, res) => {
        try {
            const { email, password } = req.body;

            const { data: user, error } = await supabase
                .from('users')
                .select('*')
                .eq('email', email.toLowerCase())
                .single();

            if (error || !user) {
                return res.status(401).json({ success: false, message: 'Invalid credentials' });
            }

            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) {
                return res.status(401).json({ success: false, message: 'Invalid credentials' });
            }

            const token = generateToken(user);

            await supabase
                .from('users')
                .update({ updated_at: new Date().toISOString() })
                .eq('id', user.id);

            res.json({
                success: true,
                message: 'Login successful',
                token,
                user: sanitizeUser(user)
            });
        } catch (error) {
            console.error('Login error:', error);
            res.status(500).json({ success: false, message: 'Login failed' });
        }
    }
);

app.post('/api/check', authenticate, async (req, res) => {
    try {
        const { data: user, error } = await supabase
            .from('users')
            .select(`
                id, email, name, role, department,
                surname, first_name, middle_name, date_of_birth,
                gender, marital_status, nationality, state_of_origin,
                lga, religion, phone, address,
                created_at, updated_at, profile_updated_at
            `)
            .eq('id', req.user.id)
            .single();

        if (error || !user) {
            return res.status(401).json({ success: false, message: 'User not found' });
        }

        res.json({ success: true, user });
    } catch (error) {
        console.error('Check error:', error);
        res.status(500).json({ success: false, message: 'Failed to verify user' });
    }
});

app.post('/api/logout', authenticate, (req, res) => {
    res.json({ success: true, message: 'Logged out successfully' });
});

app.post('/api/register',
    authenticate,
    authorize('admin'),
    [
        body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
        body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
        body('name').trim().isLength({ min: 2 }).withMessage('Name is required'),
        body('role').optional().isIn(['admin', 'security']).withMessage('Role must be admin or security'),
        body('department').optional().trim().isLength({ max: 100 })
    ],
    handleValidationErrors,
    async (req, res) => {
        try {
            const { email, password, name, role, department } = req.body;

            if (role === 'student') {
                return res.status(400).json({ success: false, message: 'Student accounts are not allowed' });
            }

            const hashedPassword = await bcrypt.hash(password, config.BCRYPT_ROUNDS);

            const { data, error } = await supabase
                .from('users')
                .insert([{
                    email: email.toLowerCase(),
                    password: hashedPassword,
                    name: name.trim(),
                    role: role || 'security',
                    department: department || null
                }])
                .select('id, email, name, role, department, created_at');

            if (error) {
                if (error.code === '23505') {
                    return res.status(409).json({ success: false, message: 'Email already exists' });
                }
                throw error;
            }

            res.status(201).json({
                success: true,
                message: 'User created successfully',
                user: data[0]
            });
        } catch (error) {
            console.error('Registration error:', error);
            res.status(500).json({ success: false, message: 'Registration failed' });
        }
    }
);

// ========== PROFILE ROUTES ==========

app.get('/api/profile', authenticate, async (req, res) => {
    res.json({ success: true, user: req.user });
});

app.put('/api/profile',
    authenticate,
    [
        body('surname').optional().trim().isLength({ max: 50 }),
        body('first_name').optional().trim().isLength({ max: 50 }),
        body('middle_name').optional().trim().isLength({ max: 50 }),
        body('date_of_birth').optional({ nullable: true }).isISO8601().withMessage('Invalid date of birth'),
        body('gender').optional({ nullable: true }).isIn(['male', 'female', 'other', 'Male', 'Female', 'Other']).withMessage('Invalid gender'),
        body('marital_status').optional({ nullable: true }).trim(),
        body('nationality').optional().trim().isLength({ max: 50 }),
        body('state_of_origin').optional().trim().isLength({ max: 50 }),
        body('lga').optional().trim().isLength({ max: 50 }),
        body('religion').optional().trim().isLength({ max: 50 }),
        body('phone').optional().trim().isLength({ max: 20 }),
        body('address').optional().trim().isLength({ max: 500 }),
        body('name').optional().trim().isLength({ min: 2, max: 100 }),
        body('department').optional().trim().isLength({ max: 100 })
    ],
    handleValidationErrors,
    async (req, res) => {
        try {
            const userId = req.user.id;
            const allowedFields = [
                'surname', 'first_name', 'middle_name', 'date_of_birth',
                'gender', 'marital_status', 'nationality', 'state_of_origin',
                'lga', 'religion', 'phone', 'address', 'name', 'department'
            ];

            const updates = {};
            for (const field of allowedFields) {
                if (req.body[field] !== undefined) {
                    updates[field] = typeof req.body[field] === 'string'
                        ? req.body[field].trim()
                        : req.body[field];
                }
            }

            if (Object.keys(updates).length === 0) {
                return res.status(400).json({ success: false, message: 'No valid fields provided for update' });
            }

            updates.profile_updated_at = new Date().toISOString();

            const { data, error } = await supabase
                .from('users')
                .update(updates)
                .eq('id', userId)
                .select(`
                    id, email, name, role, department,
                    surname, first_name, middle_name, date_of_birth,
                    gender, marital_status, nationality, state_of_origin,
                    lga, religion, phone, address,
                    created_at, updated_at, profile_updated_at
                `);

            if (error) {
                console.error('Update error:', error);
                return res.status(500).json({ success: false, message: 'Failed to update profile' });
            }

            if (!data || data.length === 0) {
                return res.status(404).json({ success: false, message: 'User not found' });
            }

            res.json({
                success: true,
                message: 'Profile updated successfully',
                user: data[0]
            });
        } catch (error) {
            console.error('Profile update error:', error);
            res.status(500).json({ success: false, message: 'Failed to update profile' });
        }
    }
);

app.post('/api/change-password',
    authenticate,
    [
        body('currentPassword').notEmpty().withMessage('Current password is required'),
        body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters')
    ],
    handleValidationErrors,
    async (req, res) => {
        try {
            const { currentPassword, newPassword } = req.body;
            const userId = req.user.id;

            const { data: user, error } = await supabase
                .from('users')
                .select('password')
                .eq('id', userId)
                .single();

            if (error || !user) {
                return res.status(404).json({ success: false, message: 'User not found' });
            }

            const isValid = await bcrypt.compare(currentPassword, user.password);
            if (!isValid) {
                return res.status(401).json({ success: false, message: 'Current password is incorrect' });
            }

            const hashedPassword = await bcrypt.hash(newPassword, config.BCRYPT_ROUNDS);

            const { error: updateError } = await supabase
                .from('users')
                .update({ password: hashedPassword, updated_at: new Date().toISOString() })
                .eq('id', userId);

            if (updateError) throw updateError;

            res.json({ success: true, message: 'Password changed successfully' });
        } catch (error) {
            console.error('Change password error:', error);
            res.status(500).json({ success: false, message: 'Failed to change password' });
        }
    }
);

// ========== HEALTH & STATS ==========

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
            database: { status: dbTest ? 'error' : 'connected', latency: `${dbLatency}ms` },
            timestamp: new Date().toISOString(),
            uptime: process.uptime()
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Service unhealthy' });
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
                    id, created_at, phone_model, location, seized_by, status,
                    persons (name, matric_number, department)
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
                        matricNumber: row.persons.matric_number,
                        department: row.persons.department
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
        res.status(500).json({ success: false, message: 'Failed to fetch dashboard data' });
    }
});

// ========== PERSONS CRUD ==========

app.get('/api/persons',
    authenticate,
    [query('search').optional().trim().isLength({ max: 100 })],
    handleValidationErrors,
    async (req, res) => {
        try {
            const { search } = req.query;

            let query = supabase
                .from('persons')
                .select('id, name, matric_number, department, level, total_seizures, last_seized, created_at');

            if (search) {
                query = query.or(
                    `name.ilike.%${search}%,matric_number.ilike.%${search}%,department.ilike.%${search}%`
                );
            }

            const { data, error } = await query.order('name');
            if (error) throw error;

            res.json({ success: true, data });
        } catch (error) {
            console.error('Get persons error:', error);
            res.status(500).json({ success: false, message: 'Failed to fetch persons' });
        }
    }
);

app.get('/api/persons/:id',
    authenticate,
    [param('id').isInt({ min: 1 }).withMessage('Invalid person ID')],
    handleValidationErrors,
    async (req, res) => {
        try {
            const { id } = req.params;

            const { data, error } = await supabase
                .from('persons')
                .select('id, name, matric_number, department, level, total_seizures, last_seized, created_at')
                .eq('id', id)
                .single();

            if (error || !data) {
                return res.status(404).json({ success: false, message: 'Person not found' });
            }

            res.json({ success: true, data });
        } catch (error) {
            console.error('Get person error:', error);
            res.status(500).json({ success: false, message: 'Failed to fetch person' });
        }
    }
);

app.post('/api/persons',
    authenticate,
    authorize('admin', 'security'),
    [
        body('name').trim().isLength({ min: 2, max: 100 }).withMessage('Name is required (2-100 chars)'),
        body('matric_number').trim().isLength({ min: 3, max: 30 }).withMessage('Matric number is required'),
        body('department').optional({ nullable: true }).trim().isLength({ max: 100 }),
        body('level').optional({ nullable: true }).trim().isLength({ max: 20 })
    ],
    handleValidationErrors,
    async (req, res) => {
        try {
            const { name, matric_number, department, level } = req.body;

            const { data, error } = await supabase
                .from('persons')
                .insert([{
                    name: name.trim(),
                    matric_number: matric_number.toUpperCase().trim(),
                    department: department?.trim() || null,
                    level: level?.trim() || null,
                    total_seizures: 0
                }])
                .select('id, name, matric_number, department, level, total_seizures, created_at');

            if (error) {
                if (error.code === '23505') {
                    return res.status(409).json({ success: false, message: 'Matric number already exists' });
                }
                throw error;
            }

            res.status(201).json({
                success: true,
                message: 'Person added successfully',
                data: data[0]
            });
        } catch (error) {
            console.error('Create person error:', error);
            res.status(500).json({ success: false, message: 'Failed to add person' });
        }
    }
);

app.put('/api/persons/:id',
    authenticate,
    authorize('admin', 'security'),
    [
        param('id').isInt({ min: 1 }).withMessage('Invalid person ID'),
        body('name').optional().trim().isLength({ min: 2, max: 100 }),
        body('matric_number').optional().trim().isLength({ min: 3, max: 30 }),
        body('department').optional({ nullable: true }).trim().isLength({ max: 100 }),
        body('level').optional({ nullable: true }).trim().isLength({ max: 20 })
    ],
    handleValidationErrors,
    async (req, res) => {
        try {
            const { id } = req.params;
            const updates = { ...req.body };

            delete updates.id;
            delete updates.created_at;
            delete updates.total_seizures;
            delete updates.last_seized;

            if (updates.matric_number) updates.matric_number = updates.matric_number.toUpperCase().trim();
            if (updates.name) updates.name = updates.name.trim();

            const { data, error } = await supabase
                .from('persons')
                .update(updates)
                .eq('id', id)
                .select('id, name, matric_number, department, level, total_seizures, last_seized, created_at');

            if (error) throw error;

            if (!data || data.length === 0) {
                return res.status(404).json({ success: false, message: 'Person not found' });
            }

            res.json({
                success: true,
                message: 'Person updated successfully',
                data: data[0]
            });
        } catch (error) {
            console.error('Update person error:', error);
            res.status(500).json({ success: false, message: 'Failed to update person' });
        }
    }
);

app.delete('/api/persons/:id',
    authenticate,
    authorize('admin'),
    [param('id').isInt({ min: 1 }).withMessage('Invalid person ID')],
    handleValidationErrors,
    async (req, res) => {
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

            res.json({ success: true, message: 'Person deleted successfully' });
        } catch (error) {
            console.error('Delete person error:', error);
            res.status(500).json({ success: false, message: 'Failed to delete person' });
        }
    }
);

// ========== SEIZURES CRUD ==========

app.get('/api/seizures',
    authenticate,
    [query('person_id').optional().isInt({ min: 1 }).withMessage('Invalid person_id')],
    handleValidationErrors,
    async (req, res) => {
        try {
            const { person_id } = req.query;

            let query = supabase
                .from('seizures')
                .select(`
                    id, person_id, phone_model, device_color, location,
                    seized_by, seizure_reason, notes, status, created_at,
                    persons (id, name, matric_number, department, level)
                `);

            if (person_id) query = query.eq('person_id', person_id);

            const { data, error } = await query.order('created_at', { ascending: false });
            if (error) throw error;

            res.json({ success: true, data });
        } catch (error) {
            console.error('Get seizures error:', error);
            res.status(500).json({ success: false, message: 'Failed to fetch seizures' });
        }
    }
);

app.get('/api/seizures/:id',
    authenticate,
    [param('id').isInt({ min: 1 }).withMessage('Invalid seizure ID')],
    handleValidationErrors,
    async (req, res) => {
        try {
            const { id } = req.params;

            const { data, error } = await supabase
                .from('seizures')
                .select(`
                    id, person_id, phone_model, device_color, location,
                    seized_by, seizure_reason, notes, status, created_at,
                    persons (id, name, matric_number, department, level)
                `)
                .eq('id', id)
                .single();

            if (error || !data) {
                return res.status(404).json({ success: false, message: 'Seizure not found' });
            }

            res.json({ success: true, data });
        } catch (error) {
            console.error('Get seizure error:', error);
            res.status(500).json({ success: false, message: 'Failed to fetch seizure' });
        }
    }
);

app.post('/api/seizures',
    authenticate,
    authorize('admin', 'security'),
    [
        body('person_id').isInt({ min: 1 }).withMessage('Valid person_id is required'),
        body('phone_model').trim().isLength({ min: 1, max: 100 }).withMessage('Phone model is required'),
        body('device_color').optional({ nullable: true }).trim().isLength({ max: 50 }),
        body('location').trim().isLength({ min: 1, max: 150 }).withMessage('Location is required'),
        body('seized_by').optional({ nullable: true }).trim().isLength({ max: 100 }),
        body('seizure_reason').optional({ nullable: true }).trim().isLength({ max: 255 }),
        body('notes').optional({ nullable: true }).trim().isLength({ max: 1000 }),
        body('status').optional().isIn(['active', 'returned', 'lost', 'draft', 'forfeited']).withMessage('Invalid status')
    ],
    handleValidationErrors,
    async (req, res) => {
        try {
            const {
                person_id, phone_model, device_color, location,
                seized_by, seizure_reason, notes, status
            } = req.body;

            const { data: person, error: personError } = await supabase
                .from('persons')
                .select('id, total_seizures')
                .eq('id', person_id)
                .single();

            if (personError || !person) {
                return res.status(404).json({ success: false, message: 'Person not found' });
            }

            const { data: seizure, error: seizureError } = await supabase
                .from('seizures')
                .insert([{
                    person_id,
                    phone_model: phone_model.trim(),
                    device_color: device_color?.trim() || null,
                    location: location.trim(),
                    seized_by: seized_by?.trim() || req.user.name,
                    seizure_reason: seizure_reason?.trim() || null,
                    notes: notes?.trim() || null,
                    status: status || 'active'
                }])
                .select();

            if (seizureError) throw seizureError;

            await supabase
                .from('persons')
                .update({
                    total_seizures: (person.total_seizures || 0) + 1,
                    last_seized: new Date().toISOString()
                })
                .eq('id', person_id);

            res.status(201).json({
                success: true,
                message: 'Seizure recorded successfully',
                data: seizure[0]
            });
        } catch (error) {
            console.error('Create seizure error:', error);
            res.status(500).json({ success: false, message: 'Failed to record seizure' });
        }
    }
);

app.put('/api/seizures/:id',
    authenticate,
    authorize('admin', 'security'),
    [
        param('id').isInt({ min: 1 }).withMessage('Invalid seizure ID'),
        body('phone_model').optional().trim().isLength({ min: 1, max: 100 }),
        body('device_color').optional({ nullable: true }).trim().isLength({ max: 50 }),
        body('location').optional().trim().isLength({ min: 1, max: 150 }),
        body('seized_by').optional({ nullable: true }).trim().isLength({ max: 100 }),
        body('seizure_reason').optional({ nullable: true }).trim().isLength({ max: 255 }),
        body('notes').optional({ nullable: true }).trim().isLength({ max: 1000 }),
        body('status').optional().isIn(['active', 'returned', 'lost', 'draft', 'forfeited'])
    ],
    handleValidationErrors,
    async (req, res) => {
        try {
            const { id } = req.params;
            const updates = { ...req.body };

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
                return res.status(404).json({ success: false, message: 'Seizure not found' });
            }

            res.json({
                success: true,
                message: 'Seizure updated successfully',
                data: data[0]
            });
        } catch (error) {
            console.error('Update seizure error:', error);
            res.status(500).json({ success: false, message: 'Failed to update seizure' });
        }
    }
);

app.delete('/api/seizures/:id',
    authenticate,
    authorize('admin'),
    [param('id').isInt({ min: 1 }).withMessage('Invalid seizure ID')],
    handleValidationErrors,
    async (req, res) => {
        try {
            const { id } = req.params;

            const { data: seizure, error: getError } = await supabase
                .from('seizures')
                .select('person_id')
                .eq('id', id)
                .single();

            if (getError || !seizure) {
                return res.status(404).json({ success: false, message: 'Seizure not found' });
            }

            const { error } = await supabase
                .from('seizures')
                .delete()
                .eq('id', id);

            if (error) throw error;

            res.json({ success: true, message: 'Seizure deleted successfully' });
        } catch (error) {
            console.error('Delete seizure error:', error);
            res.status(500).json({ success: false, message: 'Failed to delete seizure' });
        }
    }
);

// ========== ADMIN ROUTES ==========

app.get('/api/users', authenticate, authorize('admin'), async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('id, email, name, role, department, created_at, updated_at')
            .order('created_at', { ascending: false });

        if (error) throw error;

        res.json({ success: true, data });
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch users' });
    }
});

app.put('/api/users/:id/role',
    authenticate,
    authorize('admin'),
    [
        param('id').isInt({ min: 1 }).withMessage('Invalid user ID'),
        body('role').isIn(['admin', 'security']).withMessage('Role must be admin or security')
    ],
    handleValidationErrors,
    async (req, res) => {
        try {
            const { id } = req.params;
            const { role } = req.body;

            if (parseInt(id) === req.user.id && role !== 'admin') {
                return res.status(400).json({
                    success: false,
                    message: 'You cannot change your own admin role'
                });
            }

            const { data, error } = await supabase
                .from('users')
                .update({ role, updated_at: new Date().toISOString() })
                .eq('id', id)
                .select('id, email, name, role');

            if (error) throw error;

            if (!data || data.length === 0) {
                return res.status(404).json({ success: false, message: 'User not found' });
            }

            res.json({
                success: true,
                message: 'User role updated successfully',
                user: data[0]
            });
        } catch (error) {
            console.error('Update user role error:', error);
            res.status(500).json({ success: false, message: 'Failed to update user role' });
        }
    }
);

// ========== ERROR HANDLERS ==========

app.use('/api/*', (req, res) => {
    res.status(404).json({ success: false, message: 'API endpoint not found' });
});

app.get('/', (req, res) => {
    res.json({
        name: 'SeizeTrack API',
        version: '2.0.0',
        status: 'running',
        security: 'hardened',
        endpoints: {
            health: '/api/health',
            login: '/api/login',
            check: '/api/check',
            logout: '/api/logout',
            register: '/api/register',
            profile: '/api/profile',
            'change-password': '/api/change-password',
            dashboard: '/api/stats/dashboard',
            persons: '/api/persons',
            seizures: '/api/seizures',
            users: '/api/users'
        }
    });
});

app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
});

// ========== SERVER STARTUP ==========

async function startServer() {
    try {
        console.log(`🌍 Environment: ${config.NODE_ENV}`);
        console.log(`📍 Port: ${config.PORT}`);
        console.log(`🖥️  API URL: ${config.API_URL}`);
        console.log(`🔗 Client URL: ${config.CLIENT_URL}`);

        const { error } = await supabase
            .from('users')
            .select('count', { count: 'exact', head: true });

        if (error) {
            console.error('❌ Database connection failed:', error.message);
            process.exit(1);
        }

        console.log('✅ Connected to Supabase successfully!');
        console.log('🔐 JWT authentication enabled');
        console.log('🛡️  Security hardening active');
        console.log('📝 Input validation enabled');
        console.log('🚫 Password never exposed in responses');

        app.listen(config.PORT, () => {
            console.log(`🚀 Server running on port ${config.PORT}`);
        });

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