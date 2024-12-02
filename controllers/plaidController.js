require('dotenv').config();
const Stripe = require('stripe');
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const plaid = require('plaid');
const User = require('../models/userModel');
const { successResponse, errorResponse } = require('../utils/responseHelpers');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const errorCodes = require('../utils/errorCodes');

// Initialize Plaid client
// const plaidClient = new plaid.PlaidApi({
//   client_id: process.env.PLAID_CLIENT_ID,
//   secret: process.env.PLAID_SECRET,
//   environment: plaid.PlaidEnvironments.sandbox, // Corrected environment
// });

const plaidClient = new plaid.PlaidApi(
  new plaid.Configuration({
    basePath: plaid.PlaidEnvironments[process.env.PLAID_ENV || 'sandbox'],
    baseOptions: {
      headers: {
        'PLAID-CLIENT-ID': process.env.PLAID_CLIENT_ID,
        'PLAID-SECRET': process.env.PLAID_SECRET,
      },
    },
  })
);

exports.createSandboxPublicToken = async (req, res) => {
  const institutionID = 'ins_109508'; // Example institution (Platypus Credit Union)
  const initialProducts = ['auth']; // The Plaid product you want to test

  const publicTokenRequest = {
    institution_id: institutionID,
    initial_products: initialProducts,
  };

  try {
    // Step 1: Create the sandbox public token
    const publicTokenResponse = await plaidClient.sandboxPublicTokenCreate(publicTokenRequest);
    const publicToken = publicTokenResponse.data.public_token;

    // Step 2: Exchange the public token for an access token
    const exchangeRequest = {
      public_token: publicToken,
    };
    const exchangeTokenResponse = await plaidClient.itemPublicTokenExchange(exchangeRequest);
    const accessToken = exchangeTokenResponse.data.access_token;

    // Return both tokens in the response
    res.json({
      message: 'Sandbox public token created and exchanged successfully',
      public_token: publicToken,
      access_token: accessToken,
    });
  } catch (error) {
    res.status(500).json({
      error: 'Error creating or exchanging sandbox public token',
      details: error.response?.data || error.message,
    });
  }
};
// Exchange public token for access token
exports.exchangeToken = async (x, res) => {
  const { public_token} = req.body;
  try {
    const tokenResponse = await plaidClient.itemPublicTokenExchange({
      public_token:public_token, 
    });
    res.json(tokenResponse.data); 
  } catch (error) {
    console.error('Error exchanging token:', error.response?.data || error.message); 
    if (error.response) {
      console.error('Response error data:', error.response.data);
    } else {
      console.error('Error message:', error.message);
    }
    res.status(500).json({
      error: 'Error exchanging token',
      details: error.response?.data || {
        message: error.message,
        stack: error.stack
      },
    });
  }
};
exports.getPlaidLinkToken = async (req, res) => {
  const PLAID_CLIENT_ID = process.env.PLAID_CLIENT_ID;
  const PLAID_SECRET = process.env.PLAID_SECRET;
  let clientUserId = req.userId;
  // Validate userId from req and fall back to generating a UUID if invalid
  if (!clientUserId || typeof clientUserId !== 'string' || clientUserId.trim().length < 1) {
    console.warn("Invalid or missing userId. Generating a fallback UUID.");
    clientUserId = uuidv4(); // Generate a UUID if userId is invalid
  }
  const requestData = {
    client_id: PLAID_CLIENT_ID,
    secret: PLAID_SECRET,
    user: {
      client_user_id: clientUserId,
      phone_number: "+1 415 5550123",
    },
    client_name: "Personal Finance App",
    products: ["transactions"],
    transactions: {
      days_requested: 730,
    },
    country_codes: ["US"],
    language: "en",
    webhook: "https://sample-web-hook.com",
    redirect_uri: "https://domainname.com/oauth-page.html",
    account_filters: {
      depository: {
        account_subtypes: ["checking", "savings"],
      },
      credit: {
        account_subtypes: ["credit card"],
      },
    },
  };

  try {
    const response = await axios.post('https://sandbox.plaid.com/link/token/create', requestData, {
      headers: {
        'Content-Type': 'application/json',
      },
    });

    res.json(response.data);
  } catch (error) {
    console.error('Error creating Plaid link token:', error.response?.data || error.message);
    return errorResponse(res, 'Error creating Plaid link token', errorCodes.BAD_REQUEST);
  }
};

// Link Plaid account and create Stripe customer



exports.linkPlaid = async (req, res) => {
  const { public_token,} = req.body;
  const userId = req.userId;
  try {
    // Exchange Plaid public token for access token
    const tokenResponse = await plaidClient.itemPublicTokenExchange({
      public_token,
    });

    const access_token = tokenResponse.data.access_token;

    // Fetch bank account information
    console.log('Access Token:', access_token);
    const accountsResponse = await plaidClient.accountsGet({ access_token });

    // Log the account data for debugging purposes
   // console.log('Plaid accounts data:', accountsResponse.data.accounts);

    if (accountsResponse.data.accounts.length === 0) {
      return res.status(400).json({ error: 'No accounts found for this Plaid user' });
    }

    // Assume we're using the first account for this example
    const account = accountsResponse.data.accounts[0];

    // Extract the routing number and account number
    const routing_number = account.routing || account.routing_number;
    const account_number = account.account_id;

    // Check if the routing number exists, as not all accounts have it (e.g., credit cards, investment accounts)
    // if (!routing_number) {
    //   return res.status(400).json({ error: 'Cannot link account without routing number.' });
    // }

    // Default to US if country is not provided
    const country = account.country || 'US';

    // Step 1: Create a Stripe customer without the bank account first
    const customer = await stripe.customers.create({
      description: `Customer for user`,
    });

    // Step 2: Use the `sources` API to add the bank account to the created customer
    const bankAccount = await stripe.customers.createSource(customer.id, {
      source: {
        object: 'bank_account',
        country: country, // Use the country from Plaid or fallback to 'US'
        currency: 'usd',
        account_holder_name: account.name,
        account_holder_type: 'individual',
        // routing_number: '110000000', // Make sure the routing number is valid
        // account_number: '000123456789', // Ensure the correct value is used
        "routing_number":"111000000",
        "account_number":"000123456789"
      },
    });
    await User.updatePlaidDetails(public_token,customer.id,bankAccount.id,userId)
    // Return the success response with Stripe details
    return successResponse(res, 'Plaid account linked and Stripe customer created', {
      message: 'Plaid account linked and Stripe customer created',
      stripeCustomerId: customer.id,
      bankAccountId: bankAccount.id,
      accounts:accountsResponse.data.accounts,
    }, 200);
    // res.status(200).json({
    //   message: 'Plaid account linked and Stripe customer created',
    //   stripeCustomerId: customer.id,
    //   bankAccountId: bankAccount.id,
    // });
  } catch (err) {
    console.error('Error linking Plaid account:', err.message);
    res.status(500).json({ error: 'Failed to link Plaid account' });
  }
};
exports.deductPayment = async (req, res) => {
  try {
    const {amount } = req.body;
    const userId = req.userId;
    // Retrieve user info (ensure the bank account is verified)
    // const user = await User.getUserById(userId);
    // if (!user) return res.status(404).json({ error: 'User not found' });

    // Check if user's bank account is verified before attempting ACH charge
    //user.stripe_customer_id, user.stripe_bank_account_id
    const bankAccountId = 'ba_1QAaVuIW5jMD0oCf7zqlZ6dS'
    const bankAccount = await stripe.customers.retrieveSource(userId, bankAccountId);
    
    if (!bankAccount.verified) {
      return res.status(400).json({ error: 'Bank account is not verified' });
    }

    // Create an ACH charge using the verified bank account
    const charge = await stripe.charges.create({
      amount: amount * 100, // Amount in cents
      currency: 'usd',
      customer: userId,
      description: `Bi-monthly payment for User ID: ${userId}`,
      source: '000123456789' //user.stripe_bank_account_id // Bank account ID as the source
    });
    // Log the transaction in the database
  //  await Payment.logTransaction(userId, amount, charge.id, 'success');

    res.status(200).json({ message: 'Payment deducted successfully', charge });
  } catch (err) {
    console.error('Error processing payment:', err);

    // Log the failure if payment processing fails
    //await Payment.logTransaction(userId, amount, null, 'failed');
    
    res.status(500).json({ error: 'Failed to deduct payment' });
  }
};
exports.verifyBankAccount = async (req, res) => {
  try {
    const { customerId, amounts } = req.body; // amounts should be the two micro-deposits from the user
    const bankAccountId =  'ba_1QAaVuIW5jMD0oCf7zqlZ6dS';
    // Verify bank account using the micro-deposit amounts
    const bankAccount = await stripe.customers.verifySource(customerId, bankAccountId, {
      amounts: [45, 55] /// amounts // e.g., [32, 45] if the deposits were 0.32 and 0.45 cents
    });

    res.status(200).json({ message: 'Bank account verified', bankAccount });
  } catch (err) {
    console.error('Error verifying bank account:', err);
    res.status(500).json({ error: 'Failed to verify bank account' });
  }
};






// Get account information using the access token
exports.getAccountInfo = async (req, res) => {
  const { access_token } = req.body;
  try {
    const accountResponse = await plaidClient.accountsGet({ access_token });
    res.json(accountResponse.data);
  } catch (error) {
    res.status(500).json({ error: 'Error retrieving account info', details: error.message });
  }
};
