// Custom error class for sending meaningful errors
class AppError extends Error {
	constructor(message, statusCode) {
		super(message);
		this.statusCode = statusCode;
		this.status = statusCode.toString().startsWith('4') ? 'fail' : 'error';
		this.isOperational = true; // means the error was expected
		Error.captureStackTrace(this, this.constructor);
	}
}

// Handle wrong ID error from database
const handleCastErrorDB = (err) =>
	new AppError(`Invalid ${err.path}: ${err.value}`, 400);

// Handle duplicate field value error (like same email)
const handleDuplicateFieldsDB = (err) => {
	const value = err.errmsg.match(/(["'])(\\?.)*?\1/)[0];
	return new AppError(`Duplicate value: ${value}. Try something else!`, 400);
};

// Handle validation errors from DB (e.g. missing required fields)
const handleValidationErrorDB = (err) => {
	const messages = Object.values(err.errors).map((el) => el.message);
	return new AppError(`Invalid input: ${messages.join('. ')}`, 400);
};

// Handle JWT token errors
const handleJWTError = () =>
	new AppError('Invalid token. Please log in again.', 401);

const handleJWTExpiredError = () =>
	new AppError('Token expired. Please log in again.', 401);

// Show detailed error in development
const sendErrorDev = (err, res) => {
	res.status(err.statusCode).json({
		status: err.status,
		error: err,
		message: err.message,
		stack: err.stack
	});
};

// Show friendly error in production
const sendErrorProd = (err, res) => {
	if (err.isOperational) {
		res.status(err.statusCode).json({
			status: err.status,
			message: err.message
		});
	} else {
		console.error('ERROR 💥', err);
		res.status(500).json({
			status: 'error',
			message: 'Something went wrong!'
		});
	}
};

// Main error handling middleware
module.exports = (err, req, res, next) => {
	err.statusCode = err.statusCode || 500;
	err.status = err.status || 'error';

	if (process.env.NODE_ENV === 'development') {
		sendErrorDev(err, res);
	} else if (process.env.NODE_ENV === 'production') {
		let error = { ...err, message: err.message };

		if (error.name === 'CastError') error = handleCastErrorDB(error);
		if (error.code === 11000) error = handleDuplicateFieldsDB(error);
		if (error.name === 'ValidationError') error = handleValidationErrorDB(error);
		if (error.name === 'JsonWebTokenError') error = handleJWTError();
		if (error.name === 'TokenExpiredError') error = handleJWTExpiredError();

		sendErrorProd(error, res);
	}
};

// Export the custom AppError for use in other files
module.exports.AppError = AppError;
