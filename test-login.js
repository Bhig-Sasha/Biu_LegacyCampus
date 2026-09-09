const axios = require('axios');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');

// Supabase configuration
const supabase = createClient(
    'https://lsvpkromdkpvvuljxxwc.supabase.co',
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxzdnBrcm9tZGtwdnZ1bGp4eHdjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODQ4MDc1ODMsImV4cCI6MjEwMDM4MzU4M30.uffnjOfD5FzX4EIQ843no4cxUWjL793Yjcio0SEegB4'
);

async function debugLogin() {
    console.log('🔐 Starting login debug...\n');
    
    const email = 'sachatroger6@gmail.com';
    const password = 'password1';
    
    try {
        // Step 1: Check if user exists in database
        console.log('📝 Step 1: Checking if user exists in Supabase...');
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();
        
        if (error) {
            console.log('❌ User not found or RLS blocking access.');
            console.log('Error details:', error.message);
            console.log('\n💡 Please insert the user manually in Supabase SQL Editor:');
            
            // Generate hash for password
            const hash = await bcrypt.hash(password, 10);
            console.log('\n📌 Copy and run this SQL in Supabase SQL Editor:');
            console.log('-- ============================================');
            console.log('-- 1. Disable RLS (temporary)');
            console.log('ALTER TABLE users DISABLE ROW LEVEL SECURITY;');
            console.log('');
            console.log('-- 2. Delete if exists');
            console.log(`DELETE FROM users WHERE email = '${email}';`);
            console.log('');
            console.log('-- 3. Insert the user');
            console.log(`INSERT INTO users (email, password, name, role, department)`);
            console.log(`VALUES ('${email}', '${hash}', 'Sasha Troger', 'student', 'Electrical Engineering');`);
            console.log('');
            console.log('-- 4. Verify');
            console.log(`SELECT * FROM users WHERE email = '${email}';`);
            console.log('');
            console.log('-- 5. Enable RLS with proper policies (optional)');
            console.log('ALTER TABLE users ENABLE ROW LEVEL SECURITY;');
            console.log('-- ============================================\n');
            
            console.log('💡 Or use the Supabase Dashboard:');
            console.log('   1. Go to Table Editor');
            console.log('   2. Select "users" table');
            console.log('   3. Click "Insert Row"');
            console.log(`   4. Enter: email='${email}', password='${hash}', name='Sasha Troger', role='student', department='Electrical Engineering'`);
            
            console.log('\n⚠️ After inserting the user, run this script again.');
            return;
        }
        
        console.log('✅ User found in database!');
        console.log('   ID:', user.id);
        console.log('   Email:', user.email);
        console.log('   Name:', user.name);
        console.log('   Role:', user.role);
        console.log('   Hash preview:', user.password.substring(0, 30) + '...');
        console.log('   Hash length:', user.password.length);
        
        // Step 2: Test password
        console.log('\n📝 Step 2: Testing password against stored hash...');
        console.log('   Testing password:', password);
        console.log('   Stored hash:', user.password);
        
        const isMatch = await bcrypt.compare(password, user.password);
        console.log(`   Password match: ${isMatch ? '✅ YES' : '❌ NO'}`);
        
        if (!isMatch) {
            console.log('\n⚠️ Password does not match!');
            console.log('   This usually means:');
            console.log('   1. The password is wrong');
            console.log('   2. The hash was generated with a different password');
            console.log('   3. The hash was generated with different salt rounds');
            
            // Generate new hash
            const newHash = await bcrypt.hash(password, 10);
            console.log('\n📌 New hash for "password1":', newHash);
            console.log('\n💡 Run this SQL to update the password:');
            console.log(`UPDATE users SET password = '${newHash}' WHERE email = '${email}';`);
            console.log('\nThen run this script again.');
            return;
        }
        
        console.log('\n✅ Password is correct!');
        
        // Step 3: Test API login
        console.log('\n📝 Step 3: Testing API login endpoint...');
        console.log(`   POST https://biu-legacycampus.onrender.com/api/login`);
        console.log(`   Body: { email: '${email}', password: '******' }`);
        
        try {
            const response = await axios.post('https://biu-legacycampus.onrender.com/api/login', {
                email: email,
                password: password
            });
            
            console.log('✅ API Login successful!');
            console.log('   User ID:', response.data.user.id);
            console.log('   Email:', response.data.user.email);
            console.log('   Name:', response.data.user.name);
            console.log('   Role:', response.data.user.role);
            console.log('   Token:', response.data.token.substring(0, 40) + '...');
            
            // Step 4: Test authenticated endpoint
            console.log('\n📝 Step 4: Testing authenticated endpoint...');
            const profileResponse = await axios.get('https://biu-legacycampus.onrender.com/api/profile', {
                headers: {
                    'Authorization': `Bearer ${response.data.token}`
                }
            });
            
            console.log('✅ Profile fetch successful!');
            console.log('   Profile:', profileResponse.data);
            
            console.log('\n🎉 All tests passed! You can now login from the browser.');
            
        } catch (error) {
            if (error.response) {
                console.error('❌ API Login Error:');
                console.error('   Status:', error.response.status);
                console.error('   Message:', error.response.data.message || JSON.stringify(error.response.data));
                console.error('   Full response:', error.response.data);
                
                if (error.response.status === 401) {
                    console.log('\n💡 Possible issues:');
                    console.log('   1. The password hash in the database is incorrect');
                    console.log('   2. The server environment variables are not set correctly');
                    console.log('   3. The users table schema doesn\'t match the server expectations');
                }
            } else {
                console.error('❌ Error:', error.message);
            }
        }
        
    } catch (error) {
        console.error('❌ Unexpected error:', error.message);
        console.error(error.stack);
    }
}

// Call the function
debugLogin();