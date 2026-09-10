// insert-user.js
const bcrypt = require('bcrypt');

async function generateAndPrint() {
    const password = 'CampusLife2026!';  // Change this
    const hash = await bcrypt.hash(password, 12);
    
    console.log('Password:', password);
    console.log('Hash:', hash);
    console.log('\n--- SQL INSERT ---\n');
    console.log(`INSERT INTO users (email, password, name, role, department, surname, first_name, middle_name, date_of_birth, gender, marital_status, nationality, state_of_origin, lga, religion, phone, address)`);
    console.log(`VALUES (`);
    console.log(`  'campuslife.legacy@biu.edu.ng',`);
    console.log(`  '${hash}',`);
    console.log(`  'Campus Life Legacy',`);
    console.log(`  'admin',`);
    console.log(`  'Student Affairs',`);
    console.log(`  'Legacy',`);
    console.log(`  'Campus',`);
    console.log(`  'Life',`);
    console.log(`  '1990-01-15',`);
    console.log(`  'Male',`);
    console.log(`  'Single',`);
    console.log(`  'Nigeria',`);
    console.log(`  'Edo',`);
    console.log(`  'Ikpoba Okha',`);
    console.log(`  'Christianity',`);
    console.log(`  '08012345678',`);
    console.log(`  'Benson Idahosa University, Legacy Campus, Benin City, Edo State'`);
    console.log(`);`);
}

generateAndPrint();