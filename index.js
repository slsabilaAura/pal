// index.js

const express = require('express');
const app = express();
const cors = require('cors');
const helmet = require('helmet');
app.use(helmet());

require('dotenv').config();
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));

app.use(express.json());
app.use(cors());

const router = require('./routes/router.js');
app.use('/api', router);

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));