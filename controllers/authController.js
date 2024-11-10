const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const nodemailer = require('nodemailer'); // For sending emails
const crypto = require('crypto'); // For generating random OTP
const bcrypt = require('bcrypt'); // Optional: To hash the OTP before storing
const { successResponse, errorResponse } = require('../utils/responseHelpers');

exports.signup = async (req, res) => {
  const { email, password,first_name,last_name, referal_code,isLandlord, landlord_name, landlord_phone,security_amount } = req.body;
  try {
    // Check if the user already exists
    if (!email || typeof email !== 'string') {
      return errorResponse(res, 'Email is required and must be a valid string', 400);
    }

    const existingUser = await User.getUserByEmail(email);
    if (existingUser) {
      return errorResponse(res, 'User already exists', 400);
    }

    let referrer = null;
    if (referal_code) {
      // Validate referral code
      referrer = await User.getUserByReferralCode(referal_code);
      if (!referrer) {
        return errorResponse(res, 'Invalid referral code', 400);
      }
    }
    // Create new user
    const userId = await User.createUser(email, password,first_name,last_name);
    await User.updateUserStatus(userId, {
      otp_status: 'pending',
      email_status: 'pending',
      referral_status: referrer ? 'applied' : 'not applied',
      profile_completion: 'incomplete',
      landlord_status: isLandlord ? 'pending' : 'not applicable'
    });

    if (referrer) {
      await User.createReferral(referrer.id, userId, referal_code);
      await User.applyReferralBonus(referrer.id, userId);
    }
    const otp = crypto.randomInt(100000, 999999).toString();
    const hashedOtp = await bcrypt.hash(otp, 10); // Optionally hash OTP
    const otpExpiration = Date.now() + 10 * 60 * 1000; 
    await User.storeOtp(userId, hashedOtp,otpExpiration); // Store hashed OTP
    await sendOtpEmail(email, otp);
    if(security_amount){
      await User.storeSecurityDeposite(userId, security_amount);
    }
    if (isLandlord) {
      if (!landlord_name || !landlord_phone) {
        return errorResponse(res, 'Landlord name and phone are required', 500);
      }
      await User.createLandlord(userId, landlord_name, landlord_phone);
    }
    return successResponse(res, 'Signup successful. Please verify OTP sent to your email.', { userId }, 201);
  } catch (err) {
    return errorResponse(res, 'Failed to create user', 500);
  }
};
exports.userstatus = async (req, res) => {
  const { userId } = req.body;
  try {
    // Fetch OTP and expiration time from DB
    const result = await User.getUserStatus(userId);
    if (!result) {
      return errorResponse(res, 'Not data found by this user', 500);
    }
    return successResponse(res, 'Current user status', { result }, 200);
  } catch (error) {
    return errorResponse(res, 'Failed to create user', 500);
  }
};
exports.verifyOtp = async (req, res) => {
  const { userId, otp } = req.body;

  try {
    // Fetch OTP and expiration time from DB
    const { storedOtp, otpExpiration } = await User.getOtpAndExpirationByUserId(userId);

    // Check if OTP exists and hasn't expired
    if (!storedOtp || Date.now() > otpExpiration) {
      return errorResponse(res, 'OTP expired or not found', 400);
    }

    // Validate OTP
    const isOtpValid = await bcrypt.compare(otp.toString(), storedOtp);
    if (!isOtpValid) {
      return errorResponse(res, 'Invalid OTP', 400);
    }

    // Mark user as verified
    await User.verifyUser(userId);

    // Generate JWT token
    const access_token = jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({
      data: {
        message: 'OTP verified successfully',
        access_token,
        userId,
      },
    });
  } catch (error) {
    console.error('Error verifying OTP:', error.message);
    res.status(500).json({ error: 'Failed to verify OTP' });
  }
};
exports.resendOtp = async (req, res) => {
  const { userId } = req.body;
  try {
    const { otpExpiration: storedOtpExpiration } = await User.getOtpAndExpirationByUserId(userId);

    if (storedOtpExpiration && Date.now() <= storedOtpExpiration) {
      return res.status(400).json({ error: 'Current OTP is still valid. Please use the valid OTP or wait until it expires.' });
    }
    let otp = crypto.randomInt(100000, 999999).toString();
    if (otp.length !== 6) {
      otp = otp.padStart(6, '0'); // Ensure it's 6 digits
    }
    const hashedOtp = await bcrypt.hash(otp, 10);
    await User.storeOtp(userId, hashedOtp);
    const user = await User.getUserById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    await sendOtpEmail(user.email, otp);
    return res.status(200).json({
      data: {
        message: 'OTP has been resent successfully',
      },
    });
  } catch (error) {
    console.error('Error resending OTP:', error.message);
    return res.status(500).json({ error: 'Failed to resend OTP' });
  }
};

async function sendOtpEmail(email, otp) {
  try {
    const transporter = nodemailer.createTransport({
      service: 'Gmail', // Use your email provider (could be 'Gmail' or another)
      auth: {
        user: process.env.EMAIL_USER, // Your email
        pass: process.env.EMAIL_PASSWORD, // Your email password or app-specific password
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP for Signup',
      text: `Your OTP is ${otp}. Please use it to verify your account.`,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent: ' + info.response); // Log success
  } catch (error) {
    console.error('Error sending OTP email:', error.message); // Log error
    throw error; // Throw the error to handle it in the caller
  }
}

exports.verifyForgotPassword = async (req, res) => {
  const { userId, otp } = req.body;

  try {
    // Fetch OTP and expiration time from DB
    const { storedOtp, otpExpiration } = await User.getOtpAndExpirationByUserId(userId);
    // Check if OTP exists and hasn't expired
    if (!storedOtp || Date.now() > otpExpiration) {
      return errorResponse(res, 'OTP expired or not found', 400);
    }
    // Validate OTP
    const isOtpValid = await bcrypt.compare(otp.toString(), storedOtp);
    if (!isOtpValid) {
      return errorResponse(res, 'Invalid OTP', 400);
    }
    return successResponse(res, 'OTP verified successfully', { userId: userId }, 200);
  } catch (error) {
    console.error('Error verifying OTP:', error.message);
    res.status(500).json({ error: 'Failed to verify OTP' });
  }
};
exports.forgotPassword = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.getUserByEmail(email);
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    if (user) {
      const otp = crypto.randomInt(100000, 999999).toString();
      const hashedOtp = await bcrypt.hash(otp, 10); // Optionally hash OTP
      const otpExpiration = Date.now() + 10 * 60 * 1000; 
      await User.storeOtp(user.id , hashedOtp,otpExpiration); // Store hashed OTP
      await sendOtpEmail(email, otp);
    }
    return successResponse(res, 'Please verify OTP sent to your email.', { userId: user.id }, 200);
  } catch (err) {
    res.status(500).json({ error: 'Failed to login' });
  }
};
exports.login = async (req, res) => {
  const { email, password } = req.body;
  try {
    // Find user by email
    const user = await User.getUserByEmail(email);
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    // Compare passwords
    const isMatch = await User.comparePassword(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    // Generate a JWT token
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    return successResponse(res, 'Login successfully', { token, userId: user.id }, 200);
  } catch (err) {
    res.status(500).json({ error: 'Failed to login' });
  }
};
exports.changePassword = async (req, res) => {
  const { userId, password } = req.body;
  try {
    // Find user by email
    const user = await User.getUserById(userId);
    if (!user) {
      return errorResponse(res, 'User not found', 400);
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.updatePassword(userId, hashedPassword);
    return successResponse(res, 'Password changed successfully', { userId: user.id }, 200);

  } catch (err) {
    return errorResponse(res, 'Failed to login', 500);
  }
};

exports.countries = async (req, res) => {
  try {
    const counries = await User.getCountiesList();
    if (!counries) {
      return errorResponse(res, 'Failed to create user', 500);
    }
    return successResponse(res, 'country list', { counries }, 200);

  } catch (err) {
    return errorResponse(res, 'Failed to create user', 500);
  }
};
exports.cities = async (req, res) => {
  const { countryId} = req.body;
  try {
    const cities = await User.getCitiesList(countryId);
    if (!cities) {
      return errorResponse(res, 'No Record found', 500);
    }
    return successResponse(res, 'cities list', { cities }, 200);

  } catch (err) {
    return errorResponse(res, 'No Record found', 500);
  }
};
exports.zipcodelist = async (req, res) => {
  const { cityId} = req.body;
  try {
    const zipcode = await User.getZipcodeList(cityId);
    if (!zipcode) {
      return errorResponse(res, 'No Record found', 500);
    }
    return successResponse(res, 'zipcode list', { zipcode }, 200);

  } catch (err) {
    return errorResponse(res, 'No Record found', 500);
  }
};

// Middleware to protect routes
exports.protect = (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1]; // Extract token
  }

  if (!token) {
    return res.status(401).json({ error: 'Not authorized' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify token
    req.user = decoded.id; // Attach user ID to request
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token invalid or expired' });
  }
};
