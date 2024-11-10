const mysql = require('mysql2/promise');  // Ensure you are using the promise API
const dotenv = require('dotenv');

dotenv.config();

// Create a connection pool
const db = mysql.createPool({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
});

// Export the pool for use in queries
module.exports = db;
