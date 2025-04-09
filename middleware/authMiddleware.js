const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { AppError } = require('./errorMiddleware');

// Protect routes
exports.protect = async (req, res, next) => {
	try {
		let token;

		// 1) Get token from cookies
		if (req.cookies?.accessToken) {
			token = req.cookies.accessToken;
		}

		if (!token) {
			return next(new AppError('You are not logged in! Please log in to get access.', 401));
		}

		// 2) Verify token
		const decoded = jwt.verify(token, process.env.JWT_SECRET);

		// 3) Check if user still exists
		const currentUser = await User.findById(decoded.id).select('-refreshToken');
		if (!currentUser) {
			return next(new AppError('The user belonging to this token no longer exists.', 401));
		}

		// 4) Check if user changed password after the token was issued
		if (currentUser.changedPasswordAfter(decoded.iat)) {
			return next(new AppError('User recently changed password! Please log in again.', 401));
		}

		// 5) Check if user is verified
		if (!currentUser.isVerified) {
			return next(new AppError('Please verify your email to access this resource.', 401));
		}

		// 6) Grant access to protected route
		req.user = currentUser; // Set user in request object for next middleware
		res.locals.user = currentUser; // Also set in res.locals for views if needed
		next();
	} catch (err) {
		next(err);
	}
};

// Restrict to certain roles
exports.restrictTo = (...roles) => {
	return (req, res, next) => {
		if (!roles.includes(req.user.role)) {
			return next(new AppError('You do not have permission to perform this action', 403));
		}
		next();
	};
};

// Check if user is logged in (for frontend)
exports.isLoggedIn = async (req, res, next) => {
	try {
		if (req.cookies && req.cookies.accessToken) {
			// 1) Verify token
			const decoded = jwt.verify(req.cookies.accessToken, process.env.JWT_SECRET);

			// 2) Check if user still exists
			const currentUser = await User.findById(decoded.id);
			if (!currentUser) {
				return next();
			}

			// 3) Check if user changed password after the token was issued
			if (currentUser.changedPasswordAfter(decoded.iat)) {
				return next();
			}

			// THERE IS A LOGGED IN USER
			res.locals.user = currentUser;
			return next();
		}
		next();
	} catch (err) {
		return next();
	}
};