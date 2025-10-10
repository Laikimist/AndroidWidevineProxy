const fs = require('fs');
let s = fs.readFileSync(process.argv[2], 'utf8');
const parts = s.split("✄");
fs.writeFileSync(process.argv[3], parts[1].trim(), 'utf8');
