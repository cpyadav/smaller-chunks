const Stripe = require('stripe');
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// Create a bank account token
exports.createBankAccountToken = async (req, res) => {
  const { country, currency, account_holder_name, account_holder_type, routing_number, account_number } = req.body;
  try {
    const bankToken = await stripe.tokens.create({
      bank_account: {
        country,
        currency,
        account_holder_name,
        account_holder_type,
        routing_number,
        account_number,
      },
    });
    res.json(bankToken);
  } catch (error) {
    res.status(500).json({ error: 'Error creating bank account token', details: error.message });
  }
};

// Create a Stripe customer
exports.createCustomer = async (req, res) => {
  const { email, source } = req.body;
  try {
    const customer = await stripe.customers.create({ email, source });
    res.json(customer);
  } catch (error) {
    res.status(500).json({ error: 'Error creating customer', details: error.message });
  }
};

// Charge a customer
exports.chargeCustomer = async (req, res) => {
  const { amount, currency, customer } = req.body;
  try {
    const charge = await stripe.charges.create({
      amount,
      currency,
      customer,
    });
    res.json(charge);
  } catch (error) {
    res.status(500).json({ error: 'Error charging customer', details: error.message });
  }
};
