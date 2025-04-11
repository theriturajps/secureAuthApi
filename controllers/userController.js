const User = require('../models/User');
const OTP = require('../models/otpModel');
const AppError = require('../middleware/errorMiddleware').AppError;
const { generateOTP } = require('../utils/generateToken');
const { sendVerificationEmail, sendEmailChangeNotification } = require('../utils/sendEmail');
const { isValidEmail } = require('../utils/validation');

exports.getMe = async (req, res, next) => {
	try {
		const user = await User.findById(req.user._id).select('-password -refreshToken -__v -createdAt -updatedAt');

		if (!user) {
			return next(new AppError('User not found', 404));
		}

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
		// 1) Create error if user POSTs password data
		if (req.body.password || req.body.passwordConfirm) {
			return next(new AppError('This route is not for password updates. Please use /update-password.', 400));
		}

		// 2) Filter out unwanted fields - only allow bio, name, and profileImageUrl
		const allowedFields = ['bio', 'name', 'profileImageUrl'];
		const filteredBody = {};
		const updatedFields = {};

		Object.keys(req.body).forEach(field => {
			if (allowedFields.includes(field)) {
				filteredBody[field] = req.body[field];
				updatedFields[field] = req.body[field];
			}
		});

		// 3) Additional validation checks
		if (req.body.username) {
			return next(new AppError('Username cannot be updated through this endpoint', 400));
		}

		if (req.body.role) {
			return next(new AppError('Role cannot be updated through this endpoint', 400));
		}

		// 4) Handle email update separately (with OTP verification)
		if (req.body.email) {
			// Check if email format is valid
			if (!isValidEmail(req.body.email)) {
				return next(new AppError('Please provide a valid email!', 400));
			}

			// Check if new email is same as current
			if (req.body.email === req.user.email) {
				return next(new AppError('New email cannot be the same as the current email', 400));
			}

			const existingUser = await User.findOne({ email: req.body.email });
			if (existingUser) {
				return next(new AppError('Email already in use!', 400));
			}

			// Generate OTP and store it with the pending email
			const otp = generateOTP();
			await OTP.create({
				email: req.user.email,
				newEmail: req.body.email,
				otp,
				purpose: 'email-update'
			});

			// Send verification email to the NEW email address
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

		// 5) Update allowed user information
		if (Object.keys(filteredBody).length === 0) {
			return res.status(400).json({
				status: 'fail',
				message: 'No valid fields to update'
			});
		}

		const updatedUser = await User.findByIdAndUpdate(req.user._id, filteredBody, {
			new: true,
			runValidators: true
		});

		if (!updatedUser) {
			return next(new AppError('User not found', 404));
		}

		res.status(200).json({
			status: 'success',
			message: 'Profile updated successfully!',
			data: {
				updatedFields
			}
		});
	} catch (err) {
		next(err);
	}
};

exports.verifyEmailUpdate = async (req, res, next) => {
	try {
		const { otp } = req.body;
		const userId = req.user._id;

		if (!otp) {
			return next(new AppError('OTP is required', 400));
		}

		// 1) Find the most recent email update OTP for this user
		const otpRecord = await OTP.findOne({
			email: req.user.email,
			purpose: 'email-update'
		}).sort({ createdAt: -1 });

		if (!otpRecord) {
			return next(new AppError('No pending email update found!', 400));
		}

		if (otpRecord.otp !== otp) {
			return next(new AppError('Invalid OTP!', 400));
		}

		// 2) Verify the new email isn't already in use by someone else
		const emailExists = await User.findOne({
			email: otpRecord.newEmail,
			_id: { $ne: userId }  // Exclude current user
		});

		if (emailExists) {
			return next(new AppError('Email already in use!', 400));
		}

		// 3) Update the user's email
		const updatedUser = await User.findByIdAndUpdate(
			userId,
			{ email: otpRecord.newEmail, isVerified: true },
			{ new: true, runValidators: true }
		);

		if (!updatedUser) {
			return next(new AppError('User not found', 404));
		}

		// 4) Delete the OTP record
		await OTP.deleteOne({ _id: otpRecord._id });

		// 5) Send email change notification to the new email address
		await sendEmailChangeNotification(updatedUser, otpRecord.newEmail);

		// 6) Send success response
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
		// Permanently delete the user
		const deletedUser = await User.findByIdAndDelete(req.user._id);

		if (!deletedUser) {
			return next(new AppError('User not found', 404));
		}

		// Clear the accessToken cookie
		res.clearCookie('accessToken');

		res.status(200).json({
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

		if (!currentPassword || !newPassword || !newPasswordConfirm) {
			return next(new AppError('Please provide current password, new password and password confirmation', 400));
		}

		// 1) Get user from collection
		const user = await User.findById(req.user._id).select('+password');

		if (!user) {
			return next(new AppError('User not found', 404));
		}

		// 2) Check if POSTed current password is correct
		if (!(await user.comparePassword(currentPassword, user.password))) {
			return next(new AppError('Your current password is wrong.', 401));
		}

		// 3) If so, update password
		user.password = newPassword;
		user.passwordConfirm = newPasswordConfirm;
		await user.save();

		res.status(200).json({
			status: 'success',
			message: 'Password updated successfully!',
			data: {
				updatedFields: {
					password: 'updated' // We don't return the actual password
				}
			}
		});
	} catch (err) {
		next(err);
	}
};