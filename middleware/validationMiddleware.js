const validator = require('validator');
const AppError = require('./errorMiddleware').AppError;

exports.validateSignup = (req, res, next) => {
	const { username, email, password, passwordConfirm } = req.body;

	if (!username || !email || !password || !passwordConfirm) {
		return next(new AppError('Please provide all required fields!', 400));
	}

	if (!validator.isEmail(email)) {
		return next(new AppError('Please provide a valid email!', 400));
	}

	if (password !== passwordConfirm) {
		return next(new AppError('Passwords do not match!', 400));
	}

	if (password.length < 8) {
		return next(new AppError('Password must be at least 8 characters!', 400));
	}

	next();
};

exports.validateLogin = (req, res, next) => {
	const { username, password } = req.body;

	if (!username || !password) {
		return next(new AppError('Please provide username and password!', 400));
	}

	next();
};

exports.validateEmail = (req, res, next) => {
	const { email } = req.body;

	if (!email) {
		return next(new AppError('Please provide an email!', 400));
	}

	if (!validator.isEmail(email)) {
		return next(new AppError('Please provide a valid email!', 400));
	}

	next();
};

exports.validatePassword = (req, res, next) => {
	const { newPassword, newPasswordConfirm } = req.body;

	if (!newPassword || !newPasswordConfirm) {
		return next(new AppError('Please provide password and password confirmation!', 400));
	}

	if (newPassword !== newPasswordConfirm) {
		return next(new AppError('Passwords do not match!', 400));
	}

	if (newPassword.length < 8) {
		return next(new AppError('Password must be at least 8 characters!', 400));
	}

	next();
};