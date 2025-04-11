const User = require('../models/User');
const OTP = require('../models/otpModel');
const AppError = require('../middleware/errorMiddleware').AppError;
const { generateOTP } = require('../utils/generateToken');
const { sendVerificationEmail } = require('../utils/sendEmail');

exports.getMe = async (req, res, next) => {
	try {
		const user = await User.findById(req.user._id).select('-password -refreshToken -__v -createdAt -updatedAt');

		res.status(200).json({
			status: 'success',
			data: {
				user
			}
		});
	} catch (err) {
		next(err);
	}
};

exports.updateMe = async (req, res, next) => {
	try {
		if (req.body.password || req.body.passwordConfirm) {
			return next(new AppError('This route is not for password updates. Please use /update-password.', 400));
		}

		const allowedFields = ['bio', 'name', 'profileImageUrl'];
		const filteredBody = {};
		const updatedFields = {};

		Object.keys(req.body).forEach(field => {
			if (allowedFields.includes(field)) {
				filteredBody[field] = req.body[field];
				updatedFields[field] = req.body[field];
			}
		});

		if (req.body.username) {
			return next(new AppError('Username cannot be updated through this endpoint', 400));
		}

		if (req.body.role) {
			return next(new AppError('Role cannot be updated through this endpoint', 400));
		}

		if (req.body.email && req.body.email === req.user.email) {
			return next(new AppError('New email cannot be the same as the current email', 400));
		}

		if (req.body.email && req.body.email !== req.user.email) {
			const existingUser = await User.findOne({ email: req.body.email });
			if (existingUser) {
				return next(new AppError('Email already in use!', 400));
			}

			const otp = generateOTP();
			await OTP.create({
				email: req.user.email,
				newEmail: req.body.email,
				otp,
				purpose: 'email-update'
			});

			await sendVerificationEmail({ email: req.body.email }, otp);

			return res.status(200).json({
				status: 'success',
				message: 'OTP sent to new email for verification!',
				data: {
					pendingUpdate: {
						email: req.body.email
					},
					requiresVerification: true
				}
			});
		}

		const updatedUser = await User.findByIdAndUpdate(req.user._id, filteredBody, {
			new: true,
			runValidators: true
		});

		const responseData = {};
		if (Object.keys(updatedFields).length > 0) {
			responseData.updatedFields = updatedFields;
		}

		res.status(200).json({
			status: 'success',
			message: 'Profile updated successfully!',
			data: responseData
		});
	} catch (err) {
		next(err);
	}
};

exports.resendEmailUpdateOTP = async (req, res, next) => {
	try {
		const { newEmail } = req.body;

		if (!newEmail) {
			return next(new AppError('New email is required!', 400));
		}

		if (newEmail === req.user.email) {
			return next(new AppError('New email cannot be the same as current email!', 400));
		}

		const existingUser = await User.findOne({ email: newEmail });
		if (existingUser) {
			return next(new AppError('Email already in use!', 400));
		}

		const recentOTP = await OTP.findOne({
			email: req.user.email,
			purpose: 'email-update',
			createdAt: { $gt: new Date(Date.now() - 60 * 1000) }
		});

		if (recentOTP) {
			return next(
				new AppError('Please wait 1 minute before requesting another OTP.', 429)
			);
		}

		await OTP.deleteMany({ email: req.user.email, purpose: 'email-update' });

		const otp = generateOTP();
		await OTP.create({
			email: req.user.email,
			newEmail,
			otp,
			purpose: 'email-update'
		});

		await sendVerificationEmail({ email: newEmail }, otp);

		res.status(200).json({
			status: 'success',
			message: 'New OTP sent to the new email for verification!',
			data: {
				pendingUpdate: {
					email: newEmail
				},
				requiresVerification: true
			}
		});
	} catch (err) {
		next(err);
	}
};

exports.verifyEmailUpdate = async (req, res, next) => {
	try {
		const { otp } = req.body;

		if (!otp) {
			return next(new AppError('OTP is required!', 400));
		}

		const otpRecord = await OTP.findOne({
			email: req.user.email,
			purpose: 'email-update'
		}).sort({ createdAt: -1 });

		if (!otpRecord) {
			return next(new AppError('No OTP found. Please request a new email update.', 404));
		}

		if (otpRecord.otp !== otp) {
			otpRecord.attempts += 1;
			await otpRecord.save();

			if (otpRecord.attempts >= 3) {
				await OTP.deleteOne({ _id: otpRecord._id });
				return next(new AppError('Too many failed attempts. Please request a new OTP.', 400));
			}

			return next(new AppError('Invalid OTP. Please try again.', 400));
		}

		const emailExists = await User.findOne({ email: otpRecord.newEmail });
		if (emailExists) {
			return next(new AppError('Email already in use!', 400));
		}

		const updatedUser = await User.findByIdAndUpdate(
			req.user._id,
			{ email: otpRecord.newEmail, isVerified: true },
			{ new: true, runValidators: true }
		);

		await OTP.deleteOne({ _id: otpRecord._id });

		res.status(200).json({
			status: 'success',
			message: 'Email updated successfully!',
			data: {
				updatedFields: {
					email: updatedUser.email
				}
			}
		});
	} catch (err) {
		next(err);
	}
};

exports.deleteMe = async (req, res, next) => {
	try {
		await User.findByIdAndDelete(req.user._id);
		res.clearCookie('accessToken');
		res.status(204).json({
			status: 'success',
			message: 'Your account has been permanently deleted.',
			data: null
		});
	} catch (err) {
		next(err);
	}
};

exports.updatePassword = async (req, res, next) => {
	try {
		const { currentPassword, newPassword, newPasswordConfirm } = req.body;

		const user = await User.findById(req.user._id).select('+password');

		if (!(await user.comparePassword(currentPassword, user.password))) {
			return next(new AppError('Your current password is wrong.', 401));
		}

		user.password = newPassword;
		user.passwordConfirm = newPasswordConfirm;
		await user.save();

		res.status(200).json({
			status: 'success',
			message: 'Password updated successfully!',
			data: {
				updatedFields: {
					password: 'updated'
				}
			}
		});
	} catch (err) {
		next(err);
	}
};