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

async function resetAdminPassword() {
    console.log('🔄 Resetting admin password...');
    
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');
        
        // Generate new password hash
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash('admin123', salt);
        
        console.log('🔑 Generated new password hash:');
        console.log(`   First 30 chars: ${hashedPassword.substring(0, 30)}...`);
        console.log(`   Total length: ${hashedPassword.length} characters`);
        
        // Update or insert admin user
        const result = await client.query(`
            INSERT INTO users (name, email, password_hash, role, department)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (email) 
            DO UPDATE SET 
                password_hash = EXCLUDED.password_hash,
                name = EXCLUDED.name,
                role = EXCLUDED.role,
                department = EXCLUDED.department,
                updated_at = CURRENT_TIMESTAMP
            RETURNING id, email
        `, [
            'Admin User',
            'admin@seizetrack.com',
            hashedPassword,
            'admin',
            'Security Department'
        ]);
        
        await client.query('COMMIT');
        
        console.log('\n✅ Password reset successful!');
        console.log('📧 Email: admin@seizetrack.com');
        console.log('🔐 Password: admin123');
        console.log('\n⚠️  IMPORTANT: Change this password after first login!');
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ Error resetting password:', error.message);
        console.error('Stack:', error.stack);
    } finally {
        client.release();
        await pool.end();
    }
}

resetAdminPassword();