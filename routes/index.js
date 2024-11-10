const express = require('express');
const router = express.Router();

const authController = require('../controllers/authController');
const plaidController = require('../controllers/plaidController');
const stripeController = require('../controllers/stripeController');
const { protect } = require('../middleware/authMiddleware');

// Auth routes
router.post('/auth/signup', authController.signup);
router.post('/auth/verifyotp', authController.verifyOtp);
router.post('/auth/resendOtp', authController.resendOtp);
router.post('/auth/login', authController.login);

router.post('/auth/forgotpassword', authController.forgotPassword);
router.post('/auth/verifyforgotpassword', authController.verifyForgotPassword);
router.post('/auth/changePassword', authController.changePassword);
router.post('/auth/userstatus', authController.userstatus);


router.get('/auth/countries', authController.countries);
router.post('/auth/cities', authController.cities);
router.post('/auth/zipcodelist', authController.zipcodelist);
// Plaid routes
router.post('/plaid/create_sandbox_public_token', plaidController.createSandboxPublicToken);
router.post('/plaid/exchange-token',plaidController.exchangeToken);
router.post('/plaid/get_account_info', plaidController.getAccountInfo);
router.post('/plaid/link-plaid', plaidController.linkPlaid);
router.post('/plaid/deduct', plaidController.deductPayment);
router.post('/plaid/verifyBankAccount', plaidController.verifyBankAccount);


// Stripe routes
router.post('/stripe/create_bank_account_token', protect, stripeController.createBankAccountToken);
router.post('/stripe/create_customer', protect, stripeController.createCustomer);
router.post('/stripe/charge_customer', protect, stripeController.chargeCustomer);

module.exports = router;
