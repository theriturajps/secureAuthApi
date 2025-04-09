const jwt = require('jsonwebtoken');

const signToken = (id, email) => {
	const accessToken = jwt.sign({ id, email }, process.env.JWT_SECRET, {
		expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || '1h'
	});

	const refreshToken = jwt.sign({ id, email }, process.env.JWT_SECRET, {
		expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '7d'
	});

	return { accessToken, refreshToken };
};

const createSendToken = async (user, statusCode, res) => {
	try {
		const { accessToken, refreshToken } = signToken(user._id, user.email);

		// Save refresh token to user document
		user.refreshToken = refreshToken;
		await user.save({ validateBeforeSave: false });

		// Set cookies
		const cookieOptions = {
			expires: new Date(
				Date.now() + process.env.COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
			),
			httpOnly: true,
			secure: process.env.NODE_ENV === 'production',
			sameSite: 'strict'
		};

		res.cookie('accessToken', accessToken, cookieOptions);

		// Remove password from output
		user.password = undefined;
		user.refreshToken = undefined;

		res.status(statusCode).json({
			status: 'success',
			user: {
				_id: user._id,
				email: user.email,
				name: user.name,
				phone: user.phone,
				role: user.role
			}
		});
	} catch (err) {
		throw err;
	}
};

const generateOTP = () => {
	return Math.floor(100000 + Math.random() * 900000).toString();
};

module.exports = {
	signToken,
	createSendToken,
	generateOTP
};