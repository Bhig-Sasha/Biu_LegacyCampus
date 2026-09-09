const bcrypt = require('bcrypt');

async function generateHash() {
    const password = 'password1';
    const hash = await bcrypt.hash(password, 10);
    console.log('Password:', password);
    console.log('Hash:', hash);
    console.log('\nUse this SQL:');
    console.log(`INSERT INTO users (email, password, name, role, department) 
VALUES ('sachatroger6@gmail.com', '${hash}', 'Sasha Troger', 'student', 'Electrical Engineering');`);
}

generateHash();