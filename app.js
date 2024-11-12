const express = require('express');
const dotenv = require('dotenv');
dotenv.config();
const cors = require('cors');
const app = express();
const bodyParser = require('body-parser');
const routes = require('./routes');

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.get('/', (req, res) => {
  res.send('Server is running');
});
// API Routes
app.use('/api', routes);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
