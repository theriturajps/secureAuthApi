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

		// 3) Check if any fields are actually updated

		if (req.body.username) {
			return next(new AppError('Username cannot be updated through this endpoint', 400));
		}

		if (req.body.role) {
			return next(new AppError('Role cannot be updated through this endpoint', 400));
		}

		if (req.body.email === req.user.email) { 
			return next(new AppError('New email cannot be the same as the current email', 400));
		}

		// 4) Handle email update separately (with OTP verification)
		if (req.body.email && req.body.email !== req.user.email) {

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
		await User.findByIdAndUpdate(req.user._id, filteredBody, {
			new: true,
			runValidators: true
		});

		const responseData = {}; // To store the response data
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

exports.verifyEmailUpdate = async (req, res, next) => {
	try {
		const { otp } = req.body;
		const userId = req.user._id;

		// 1) Find the most recent email update OTP for this user
		const otpRecord = await OTP.findOne({
			email: req.user.email,
			purpose: 'email-update'
		}).sort({ createdAt: -1 });

		if (!otpRecord || otpRecord.otp !== otp) {
			return next(new AppError('Invalid OTP or OTP expired!', 400));
		}

		// 2) Verify the new email isn't already in use
		const emailExists = await User.findOne({ email: otpRecord.newEmail });
		if (emailExists) {
			return next(new AppError('Email already in use!', 400));
		}

		// 3) Update the user's email
		const updatedUser = await User.findByIdAndUpdate(
			userId,
			{ email: otpRecord.newEmail, isVerified: true },
			{ new: true, runValidators: true }
		);

		// 4) Delete the OTP record
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
		// Permanently delete the user
		await User.findByIdAndDelete(req.user._id);

		// Clear the accessToken cookie
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

		// 1) Get user from collection
		const user = await User.findById(req.user._id).select('+password');

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
}