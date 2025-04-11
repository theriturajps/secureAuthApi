const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const authMiddleware = require('../middleware/authMiddleware');
const validationMiddleware = require('../middleware/validationMiddleware');

router.use(authMiddleware.protect);

router.get('/me', userController.getMe);
router.patch('/update-me', userController.updateMe);
router.delete('/delete-me', userController.deleteMe);
router.patch('/update-password', validationMiddleware.validatePassword, userController.updatePassword);

// Email update routes
router.post('/verify-email-update', userController.verifyEmailUpdate);
router.post('/resend-email-update-otp', userController.resendEmailUpdateOTP);

module.exports = router;