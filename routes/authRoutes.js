const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const validationMiddleware = require('../middleware/validationMiddleware');
const authMiddleware = require('../middleware/authMiddleware');

router.get('/protected-route', authMiddleware.protect, (req, res) => {
	res.json({ user: req.user });
});

router.post('/signup', validationMiddleware.validateSignup, authController.signup);
router.post('/verify-email', authController.verifyEmail);
router.post('/login', validationMiddleware.validateLogin, authController.login);

router.post('/forgot-password', validationMiddleware.validateEmail, authController.forgotPassword);
router.post('/verify-reset-otp', authController.verifyPasswordResetOTP);
router.post('/reset-password', validationMiddleware.validatePassword, authController.resetPassword);

router.get('/logout', authMiddleware.protect, authController.logout); // protected route
router.post('/refresh-token', authMiddleware.protect, authController.refreshToken); // protected route

module.exports = router;