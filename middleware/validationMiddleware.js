const { isValidEmail, isEmpty, isMinLength, doStringsMatch } = require('../utils/validation');
const { AppError } = require('./errorMiddleware');

exports.validateSignup = (req, res, next) => {
	const { username, email, password, passwordConfirm } = req.body;

	if (isEmpty(username) || isEmpty(email) || isEmpty(password) || isEmpty(passwordConfirm)) {
		return next(new AppError('Please provide all required fields!', 400));
	}

	if (!isValidEmail(email)) {
		return next(new AppError('Please provide a valid email!', 400));
	}

	if (!doStringsMatch(password, passwordConfirm)) {
		return next(new AppError('Passwords do not match!', 400));
	}

	if (!isMinLength(password, 8)) {
		return next(new AppError('Password must be at least 8 characters!', 400));
	}

	next();
};

exports.validateLogin = (req, res, next) => {
	const { username, password } = req.body;

	if (isEmpty(username) || isEmpty(password)) {
		return next(new AppError('Please provide username and password!', 400));
	}

	next();
};

exports.validateEmail = (req, res, next) => {
	const { email } = req.body;

	if (isEmpty(email)) {
		return next(new AppError('Please provide an email!', 400));
	}

	if (!isValidEmail(email)) {
		return next(new AppError('Please provide a valid email!', 400));
	}

	next();
};

exports.validatePassword = (req, res, next) => {
	const { newPassword, newPasswordConfirm } = req.body;

	if (isEmpty(newPassword) || isEmpty(newPasswordConfirm)) {
		return next(new AppError('Please provide password and password confirmation!', 400));
	}

	if (!doStringsMatch(newPassword, newPasswordConfirm)) {
		return next(new AppError('Passwords do not match!', 400));
	}

	if (!isMinLength(newPassword, 8)) {
		return next(new AppError('Password must be at least 8 characters!', 400));
	}

	next();
};