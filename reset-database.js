// reset-database.js
require("dotenv").config();
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const config = {
    DB_USER: process.env.DB_USER || 'postgres',
    DB_HOST: process.env.DB_HOST || 'localhost',
    DB_NAME: process.env.DB_NAME || 'seizetrack',
    DB_PASSWORD: process.env.DB_PASSWORD || '',
    DB_PORT: process.env.DB_PORT || 5432,
};

const pool = new Pool({
    user: config.DB_USER,
    host: config.DB_HOST,
    database: config.DB_NAME,
    password: config.DB_PASSWORD,
    port: config.DB_PORT,
});

async function resetDatabase() {
    console.log('🔄 Resetting database...');
    
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');
        
        // Drop and recreate tables with correct structure
        console.log('📊 Recreating tables...');
        
        await client.query('DROP TABLE IF EXISTS seizures CASCADE');
        await client.query('DROP TABLE IF EXISTS persons CASCADE');
        await client.query('DROP TABLE IF EXISTS users CASCADE');
        
        // Create users table with password column (not password_hash)
        await client.query(`
            CREATE TABLE users (
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
        
        // Create persons table
        await client.query(`
            CREATE TABLE persons (
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
        
        // Create seizures table
        await client.query(`
            CREATE TABLE seizures (
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
        
        // Create indexes
        await client.query(`CREATE INDEX idx_persons_matric ON persons(matric_number)`);
        await client.query(`CREATE INDEX idx_seizures_person_id ON seizures(person_id)`);
        await client.query(`CREATE INDEX idx_seizures_created_at ON seizures(created_at)`);
        await client.query(`CREATE INDEX idx_seizures_status ON seizures(status)`);
        
        // Create admin user with PROPER bcrypt hash
        console.log('👤 Creating admin user...');
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash('admin123', salt);
        
        await client.query(`
            INSERT INTO users (name, email, password, role, department)
            VALUES ($1, $2, $3, $4, $5)
        `, [
            'Admin User',
            'admin@seizetrack.com',
            hashedPassword,
            'admin',
            'Security Department'
        ]);
        
        // Create a test security user
        const testHash = await bcrypt.hash('security123', salt);
        await client.query(`
            INSERT INTO users (name, email, password, role, department)
            VALUES ($1, $2, $3, $4, $5)
        `, [
            'Security Officer',
            'security@seizetrack.com',
            testHash,
            'security',
            'Security Department'
        ]);
        
        // Add some sample data for testing
        console.log('📝 Adding sample data...');
        
        // Add sample persons
        await client.query(`
            INSERT INTO persons (name, matric_number, department, level)
            VALUES 
            ('John Doe', 'SCI/20/001', 'Computer Science', '200'),
            ('Jane Smith', 'ENG/19/045', 'Electrical Engineering', '300'),
            ('Mike Johnson', 'MTH/21/023', 'Mathematics', '100')
        `);
        
        await client.query('COMMIT');
        
        console.log('\n✅ Database reset successful!');
        console.log('\n📋 Login Credentials:');
        console.log('====================');
        console.log('👑 Admin User:');
        console.log('   Email: admin@seizetrack.com');
        console.log('   Password: admin123');
        console.log('\n🛡️ Security User:');
        console.log('   Email: security@seizetrack.com');
        console.log('   Password: security123');
        console.log('\n⚠️  IMPORTANT: Change passwords after first login!');
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ Error resetting database:', error.message);
    } finally {
        client.release();
        await pool.end();
    }
}

resetDatabase();