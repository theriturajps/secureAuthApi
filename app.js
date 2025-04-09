const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const errorHandler = require('./middleware/errorMiddleware');

// Route files
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');

const app = express();

// Set security headers
app.use(helmet());

// Enable CORS
app.use(cors({
	origin: process.env.FRONTEND_URL,
	credentials: true
}));

// Rate limiting
const limiter = rateLimit({
	windowMs: 10 * 60 * 1000, // 10 mins
	max: 100
});
app.use(limiter);

// Body parser
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));

// Cookie parser
app.use(cookieParser());

// Mount routers
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/user', userRoutes);

// Error handler middleware
app.use(errorHandler);

module.exports = app;