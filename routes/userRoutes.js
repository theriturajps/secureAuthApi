const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const authMiddleware = require('../middleware/authMiddleware');
const validationMiddleware = require('../middleware/validationMiddleware');

// Protect all routes after this middleware
router.use(authMiddleware.protect);

router.get('/me', userController.getMe);
router.patch('/update-me', userController.updateMe);
router.post('/verify-email-update', userController.verifyEmailUpdate);
router.delete('/delete-me', userController.deleteMe);
router.patch('/update-password', validationMiddleware.validatePassword, userController.updatePassword);

module.exports = router;