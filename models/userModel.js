const db = require('../models/db');
const bcrypt = require('bcryptjs');

const User = {
  // Create user with hashed password
  createUser: async (email, password, first_name, last_name, referred_by = null) => {
    try {
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Generate a unique referral code
      const referral_code = User.generateReferralCode(first_name, last_name);
  
      // Default values for referral bonus and account balance
      const referral_bonus = 0.00;
      const account_balance = 0.00;
  
      // Ensure that 'referred_by' is either a valid value or null
      referred_by = referred_by || null;
  
      // Perform the INSERT query
      const [result] = await db.execute(
        `INSERT INTO users (first_name, last_name, email, password, referral_code, referral_bonus, account_balance, referred_by) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [first_name || '', last_name || '', email, hashedPassword, referral_code, referral_bonus, account_balance, referred_by]
      );
  
      return result.insertId; // Return the newly created user ID
    } catch (error) {
      console.error('Error creating user:', error.message);
      throw error; // Rethrow the error for higher-level handling
    }
  },  
  updateUserStatus: async (userId, statusUpdates) => {
    const { otp_status, email_status, referral_status, profile_completion, landlord_status } = statusUpdates;

    try {
      const sql = `
      UPDATE users
      SET otp_status = ?, email_status = ?, referral_status = ?, profile_completion = ?, landlord_status = ?
      WHERE id = ?`;
      const [result] = await db.execute(sql, [
        otp_status,
        email_status,
        referral_status,
        profile_completion,
        landlord_status,
        userId
      ]);
      return result;
    } catch (error) {
      console.error('Error updating user status:', error.message);
      throw error; // Rethrow the error for higher-level handling
    }
  },  
  getUserByReferralCode : async (referralCode) => {
    try {
      const [rows] = await db.execute('SELECT * FROM users WHERE referral_code = ?', [referralCode]);
      return rows.length > 0 ? rows[0] : null;
    } catch (error) {
      console.error('Error getting user by referral code:', error.message);
      throw error;
    }
  },
  generateReferralCode: (firstName, lastName) => {
    const randomNum = Math.floor(1000 + Math.random() * 9000); // 4-digit random number
    return `${firstName.substring(0, 3).toUpperCase()}${lastName.substring(0, 3).toUpperCase()}${randomNum}`;
  },

  createReferral: async (referrerId, referredUserId, referralCode) => {
    try {
      await db.execute('INSERT INTO referrals (referrer_id, referred_user_id, referral_code) VALUES (?, ?, ?)', [referrerId, referredUserId, referralCode]);
    } catch (error) {
      console.error('Error creating referral:', error.message);
      throw error;
    }
  },  
  applyReferralBonus: async (referrerId, referredUserId) => {
    try {
      await db.execute('UPDATE users SET referral_bonus = referral_bonus + 10 WHERE id = ?', [referrerId]);
    } catch (error) {
      console.error('Error applying referral bonus:', error.message);
      throw error;
    }
  },
  getUserByEmail: async (email) => {
    try {
      const [rows, fields] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
      if (rows.length === 0) {
        console.log('No user found with this email.');
        return null; // Return null if no user exists
      }
  
      return rows[0]; // Return the first user found
    } catch (error) {
      console.error('Error fetching user by email:', error.message);
      throw error; // Rethrow the error for higher-level handling
    }
  },  
  getUserStatus: async (userId) => {
    try {
      const [rows, fields] = await db.execute('SELECT * FROM users WHERE id = ?', [userId]);
      if (rows.length === 0) {
        console.log('No user found with this userId');
        return null; // Return null if no user exists
      }
  
      return rows[0]; // Return the first user found
    } catch (error) {
      console.error('Error fetching user by email:', error.message);
      throw error; // Rethrow the error for higher-level handling
    }
  },
  storeOtp: async (userId, otp) => {
    const otpExpiration = Date.now() + 1 * 60 * 1000;
    const [result] = await db.execute(
      'UPDATE users SET verify_otp = ?, otp_expiration = ? WHERE id = ?',
      [otp, otpExpiration, userId]
    );
    return result;
  },
  storeSecurityDeposite: async (userId,securityAmount) =>{
    try {
      await db.execute('INSERT INTO security_deposits (user_id, amount, payment_method,status) VALUES (?, ?, ?,?)', [userId, securityAmount, 'ACH', 'Pending']);
    } catch (error) {
      console.error('Error creating referral:', error.message);
      throw error;
    }
  },
  getOtpAndExpirationByUserId: async (userId) => {
    const [rows] = await db.execute(
      'SELECT verify_otp, otp_expiration FROM users WHERE id = ?',
      [userId]
    );
  
    if (rows.length === 0) {
      return null;
    }
  
    const { verify_otp, otp_expiration } = rows[0];
    return { storedOtp: verify_otp, otpExpiration: otp_expiration };
  },  
  createLandlord: async (userId, name, phone) => {
    try {
      await db.execute(
        'INSERT INTO landlords (user_id, name, phone) VALUES (?, ?, ?)',
        [userId, name, phone]
      );
    } catch (error) {
      console.error('Error creating landlord entry:', error.message);
      throw error;
    }
  },  
  updatePlaidDetails: async (plaid_access_token,stripe_customer_id,stripe_payment_method_id, userId) => {
    await db.execute('UPDATE users SET plaid_access_token = ?,stripe_customer_id = ?,stripe_payment_method_id =?   WHERE id = ?', [plaid_access_token,stripe_customer_id,stripe_payment_method_id, userId]);
  },  
  updateStatus: async (userId, status) => {
    await db.execute('UPDATE users SET status = ? WHERE id = ?', [status, userId]);
  },  
  updateOtpVerified: async (userId, isVerified) => {
    await db.execute('UPDATE users SET otp_verified = ? WHERE id = ?', [isVerified, userId]);
  },  
  updatePassword: async (userId, hashedPassword) => {
    await db.execute(
      'UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?',
      [hashedPassword, userId]
    );
  },   
  verifyUser: async (userId) => {
    const [result] = await db.execute(
      'UPDATE users SET verify_otp = NULL, otp_status = ? WHERE id = ?',
      ['verified', userId]
    );
    return result;
  },
  getOtpByUserId: async (userId) => {
    const [rows] = await db.execute('SELECT verify_otp FROM users WHERE id = ?', [userId]);
    return rows.length > 0 ? rows[0].verify_otp : null;
  },
  getUserById: async (userId) => {
    const [rows] = await db.execute('SELECT email,verify_otp,id FROM users WHERE id = ?', [userId]);
    return rows.length > 0 ? rows[0] : null;
  },
  getCountiesList: async () => {
    const [rows] = await db.execute('SELECT * FROM countries');
    return rows.length > 0 ? rows : null;
  },
  getCitiesList: async (countryId) => {
    const [rows] = await db.execute('SELECT * FROM cities WHERE country_id = ?',[countryId]);
    return rows.length > 0 ? rows : null;
  },
  getZipcodeList: async (cityId) => {
    const [rows] = await db.execute('SELECT * FROM zipcode WHERE city_id = ?',[cityId]);
    return rows.length > 0 ? rows : null;
  },
  // Compare password during login
  comparePassword: async (enteredPassword, storedPassword) => {
    return await bcrypt.compare(enteredPassword, storedPassword);
  }
};

module.exports = User;
