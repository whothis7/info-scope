const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const session = require('express-session');
const path = require('path');
const { spawn } = require('child_process');
const rateLimit = require('express-rate-limit');
const Stripe = require('stripe');

const app = express();

const stripe = Stripe('sk_test_51Pw1UcGBOD6BX2Y34oMUbHpeN3hJurxKaf5sRtnsrco4ScezVB1WEiplGd2o9TBtFilq4JGHaOmUBXBUghBj7Ptv00yj7neIn7'); // Use your Stripe secret key

app.use(express.static('public'));
app.use('/webhook', express.raw({type: 'application/json'}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session middleware
app.use(session({
    secret: 'mysecretkey',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set `true` if using HTTPS
}));

mongoose.connect('mongodb://localhost:27017', {
    serverSelectionTimeoutMS: 5000,
  }).then(() => console.log('MongoDB connected'))
    .catch(err => console.log('MongoDB connection error:', err));

// Define user schema
const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    requestsRemaining: {
        type: Number,
        default: 10 // Each user starts with 10 requests
    }
});

const User = mongoose.model('User', userSchema);

// User registration
app.post('/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Email validation
        const MIN_EMAIL_LENGTH = 15;
        if (!email.includes('@') || email.length < MIN_EMAIL_LENGTH) {
            return res.status(400).json({
                error: 'Invalid email format',
                details: 'Try again.'
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
            return res.status(400).json({
                error: 'Email already registered',
                details: 'This email is already associated with an account'
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user with 10 requests
        const newUser = new User({ email, password: hashedPassword, requestsRemaining: 10 });
        await newUser.save();

        console.log('User saved successfully in DB');

        // Automatically log in after registration
        req.session.user = { id: newUser._id, email: newUser.email };
        return res.status(201).json({ message: 'Registered Successfully. You can now login.' });
    } catch (err) {
        console.error('Error', err);
        res.status(500).json({
            error: 'An error occurred',
            details: 'There was a problem processing your request'
        });
    }
});

// User login
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user by email
        const registeredUser = await User.findOne({ email: email });
        if (!registeredUser) {
            return res.status(401).json({ error: 'Email not registered.' });
        }

        // Compare password with hashed password in database
        const passwordMatch = await bcrypt.compare(password, registeredUser.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Incorrect password.' });
        }

        // Create session
        req.session.user = {
            id: registeredUser._id,
            email: registeredUser.email
        };

        return res.status(200).json({ message: 'Login successful' });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ error: 'An error occurred during login. Please try again.' });
    }
});

app.get('/logout', (req, res) => {
    // Destroy the session
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ error: 'Failed to log out. Please try again.' });
        }
        
        // Clear the cookie
        res.clearCookie('connect.sid'); // Assumes you are using the default cookie name 'connect.sid'

        // Redirect to the login or home page after logout
        res.redirect('/'); // Adjust this URL to match your login page or home page
    });
});

// Dashboard route
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/public/dashboard.html');
});

// Create checkout session for Pro Tier
app.post('/create-checkout-session-pro', async (req, res) => {
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [{
                price: 'price_1PwqOpGBOD6BX2Y3742aQhPl', // Pro Tier Price ID
                quantity: 1,
            }],
            mode: 'payment',
            success_url: 'http://localhost:3000/success?session_id={CHECKOUT_SESSION_ID}',
            cancel_url: 'http://localhost:3000/cancel',
        });

        res.json({ id: session.id });
    } catch (error) {
        console.error('Stripe checkout error:', error);
        res.status(500).send('Error creating Stripe checkout session');
    }
});

// Create checkout session for Premium Tier
app.post('/create-checkout-session-premium', async (req, res) => {
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [{
                price: 'price_1PyK2AGBOD6BX2Y3GA3YW1vo', // Premium Tier Price ID
                quantity: 1,
            }],
            mode: 'payment',
            success_url: 'http://localhost:3000/success?session_id={CHECKOUT_SESSION_ID}',
            cancel_url: 'http://localhost:3000/cancel',
        });

        res.json({ id: session.id });
    } catch (error) {
        console.error('Stripe checkout error:', error);
        res.status(500).send('Error creating Stripe checkout session');
    }
});

// Fulfill the checkout session
async function fulfillCheckout(sessionId) {
    console.log(`Fulfilling Checkout Session ${sessionId}`);

    try {
        console.log(`Retrieving session ${sessionId} from Stripe`);
        const checkoutSession = await stripe.checkout.sessions.retrieve(sessionId, {
            expand: ['line_items'],
        });

        if (checkoutSession.payment_status !== 'paid') {
            console.log(`Session ${sessionId} payment status is not paid`);
            throw new Error('Payment not completed');
        }

        const priceId = checkoutSession.line_items.data[0].price.id;
        console.log(`Price ID for session ${sessionId}: ${priceId}`);

        console.log(`Finding user with email ${checkoutSession.customer_email}`);
        const user = await User.findOne({ email: checkoutSession.customer_email });

        if (!user) {
            console.log(`User not found for email ${checkoutSession.customer_email}`);
            throw new Error('User not found');
        }

        let requestsToAdd = 0;
        switch (priceId) {
            case 'price_1PwqOpGBOD6BX2Y3742aQhPl':
                requestsToAdd = 500; // Pro tier
                break;
            case 'price_1PyK2AGBOD6BX2Y3GA3YW1vo':
                requestsToAdd = 1000; // Premium tier
                break;
            default:
                console.log(`Unknown price ID: ${priceId}`);
                throw new Error('Unknown price ID');
        }

        console.log(`Adding ${requestsToAdd} requests to user ${user.email}`);
        user.requestsRemaining += requestsToAdd;
        await user.save();

        console.log(`User ${user.email} successfully updated with ${user.requestsRemaining} requests.`);
    } catch (error) {
        console.error('Error in fulfillCheckout:', error);
        // Implement retry logic or alert system here
    }
}

const checkStripeEvents = async () => {
    try {
      const events = await stripe.events.list({
        limit: 100,
        created: {
          gte: Math.floor(Date.now() / 1000) - 3600 // Check last hour
        }
      });
  
      for (const event of events.data) {
        await processWebhookEvent(event);
      }
    } catch (error) {
      console.error('Error checking Stripe events:', error);
    }
  };
  
  // Run every hour
  setInterval(checkStripeEvents, 60 * 60 * 1000);

// Stripe webhook endpoint
app.use(express.json());

async function processWebhookEvent(event) {
  console.log('Processing event:', event.type);
  switch (event.type) {
    case 'charge.succeeded':
      console.log('Processing successful charge');
      // Handle successful charge
      break;
    case 'charge.refunded':
      console.log('Processing refund event');
      await handleRefund(event.data.object);
      break;
    case 'charge.refund.updated':
      console.log('Processing refund update event');
      // You might want to handle this separately if needed
      break;
    case 'checkout.session.completed':
      console.log('Processing completed checkout session');
      await fulfillCheckout(event.data.object.id);
      break;
    // Add other event types as needed
    default:
      console.log(`Unhandled event type ${event.type}`);
  }
}

// Use this function in your webhook route
app.post('/webhook', async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const webhookSecret = 'whsec_b551d9f822f3a29a37354e938fdce30d9cdd04bfab7d1646f2caa9319b2d5cc0'; // Your actual webhook secret
  
    try {
      const event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
      
      // Respond immediately
      res.sendStatus(200);
  
      // Process event asynchronously
      setImmediate(async () => {
        try {
          await processWebhookEvent(event);
        } catch (error) {
          console.error('Error processing event:', error);
        }
      });
    } catch (err) {
      console.error(`Webhook Error: ${err.message}`);
      res.status(400).send(`Webhook Error: ${err.message}`);
    }
  });
  
  async function processWebhookEvent(event) {
    console.log('Processing event:', event.type);
    switch (event.type) {
      case 'charge.refunded':
        console.log('Processing refund event');
        await handleRefund(event.data.object);
        break;
      case 'charge.refund.updated':
        console.log('Processing refund update event');
        // You might want to handle this separately if needed
        break;
      // ... other event types ...
      default:
        console.log(`Unhandled event type ${event.type}`);
    }
  }

  async function handleRefund(charge) {
    console.time('handleRefund');
    try {
      const customerEmail = charge.billing_details.email;
      const refundAmount = charge.amount_refunded / 100;
      const totalChargeAmount = charge.amount / 100;
  
      console.log(`Processing refund: email=${customerEmail}, refundAmount=${refundAmount}, totalChargeAmount=${totalChargeAmount}`);
  
      const user = await User.findOne({ email: customerEmail });
      if (!user) {
        console.log(`User not found for email ${customerEmail}`);
        return;
      }
  
      let requestsToRemove = calculateRequestsToRemove(totalChargeAmount, refundAmount);
  
      user.requestsRemaining = Math.max(0, user.requestsRemaining - requestsToRemove);
      await user.save();
  
      console.log(`User ${user.email} updated: Removed ${requestsToRemove} requests. ${user.requestsRemaining} requests remaining.`);
    } catch (error) {
      console.error('Error handling refund:', error);
    } finally {
      console.timeEnd('handleRefund');
    }
  }
  
  function calculateRequestsToRemove(totalChargeAmount, refundAmount) {
    if (totalChargeAmount === 7.99) {
      return Math.floor(500 * (refundAmount / totalChargeAmount));
    } else if (totalChargeAmount === 12.99) {
      return Math.floor(1000 * (refundAmount / totalChargeAmount));
    } else {
      return Math.floor(refundAmount * 30);
    }
  }

async function processCheckoutAsync(sessionId) {
    try {
        await fulfillCheckout(sessionId);
        console.log(`Checkout fulfilled successfully for session ${sessionId}`);
    } catch (error) {
        console.error(`Error fulfilling checkout for session ${sessionId}:`, error);
        // Implement retry logic or alert system here
    }
}

// Success route after payment
app.get('/success', isAuthenticated, async (req, res) => {
    try {
        // Retrieve the latest session for this user
        const sessions = await stripe.checkout.sessions.list({
            limit: 1,
            customer: req.session.user.stripeCustomerId,
        });

        if (sessions.data.length === 0) {
            return res.status(400).send('No recent checkout session found');
        }

        const session = sessions.data[0];

        // Log session details for debugging
        console.log('Session details:', {
            id: session.id,
            paymentStatus: session.payment_status,
            amountTotal: session.amount_total,
            currency: session.currency
        });

        // Verify the payment was successful
        if (session.payment_status === 'paid') {
            // Get the current user
            const user = await User.findById(req.session.user.id);

            if (!user) {
                throw new Error('User not found');
            }

            // Determine the number of requests to add based on the price
            let requestsToAdd = 0;
            const amountInEuros = session.amount_total / 100; // Convert cents to euros
            
            if (amountInEuros === 7.99) { // €7.99
                requestsToAdd = 500; // Pro tier
            } else if (amountInEuros === 12.99) { // €29.99
                requestsToAdd = 1000; // Premium tier
            } else {
                console.log(`Unexpected price: €${amountInEuros}`);
                // Instead of throwing an error, we'll add a default number of requests
                requestsToAdd = Math.floor(amountInEuros * 30); // 30 requests per euro as a fallback
            }

            // Update the user's account
            user.requestsRemaining += requestsToAdd;
            await user.save();

            console.log(`Updated user ${user.email} with ${requestsToAdd} additional requests`);

            res.send(`
                <html>
                    <head><title>Payment Success</title></head>
                    <body style="font-family: Arial, sans-serif; text-align: center;">
                        <h1>Payment Successful!</h1>
                        <p>Your purchase of €${amountInEuros.toFixed(2)} was successful, and your account has been updated with ${requestsToAdd} additional requests.</p>
                        <a href="/dashboard">Return to Dashboard</a>
                    </body>
                </html>
            `);
        } else {
            throw new Error(`Payment not successful. Status: ${session.payment_status}`);
        }
    } catch (error) {
        console.error('Error processing successful payment:', error);
        res.status(500).send(`
            <html>
                <head><title>Payment Processing Error</title></head>
                <body style="font-family: Arial, sans-serif; text-align: center;">
                    <h1>Error Processing Payment</h1>
                    <p>There was an error processing your payment. Please contact support if this issue persists.</p>
                    <p>Error details: ${error.message}</p>
                    <a href="/dashboard">Return to Dashboard</a>
                </body>
            </html>
        `);
    }
});

// Helper to check if user is authenticated
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login');
    }
}

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/terms', (req,res) => {
    res.sendFile(path.join(__dirname, 'public', 'terms.html'))
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Rate limiting middleware for '/extract_entities'
const limiter = rateLimit({
    windowMs: 24 * 60 * 60 * 1000, // 24 hours
    max: 10, // Limit each IP to 10 requests per day
    handler: (req, res) => {
        return res.status(429).json({
            error: 'Too many requests. You can only make 10 requests per day.',
        });
    }
});

// POST route to handle entity extraction with word limit check
app.post('/extract_entities', async (req, res) => {
    const text = req.body.text;

    if (!text) {
        return res.status(400).send({ error: 'No text provided' });
    }

    const wordCount = text.split(/\s+/).length; // Simple word count
    if (wordCount > 500) {
        return res.status(400).json({
            error: 'Text exceeds the 500-word limit.',
        });
    }

    // Check if the user is logged in
    if (req.session.user) {
        // Logged-in users
        const user = await User.findById(req.session.user.id);

        // Check if the user has remaining requests
        if (user.requestsRemaining <= 0) {
            return res.status(403).json({
                error: 'No remaining requests. Buy more requests.'
            });
        }

        // Decrement the user's requestsRemaining after a successful request
        user.requestsRemaining -= 1;
        await user.save();

        // Call the Python script using child_process
        handlePythonProcess(req, res, text); // Call to handle Python extraction
    } else {
        // Unauthenticated users: Use the rate limit middleware
        limiter(req, res, () => {
            // Call the Python script using child_process
            handlePythonProcess(req, res, text); // Call to handle Python extraction
        });
    }
});

// Function to handle Python script call for extraction
function handlePythonProcess(req, res, text) {
    const pythonProcess = spawn('python', ['extract_entities.py'], {
        stdio: ['pipe', 'pipe', 'pipe'],
    });

    pythonProcess.stdin.setEncoding('utf-8');
    pythonProcess.stdout.setEncoding('utf-8');

    pythonProcess.stdin.write(text); // Pass the input text to Python script
    pythonProcess.stdin.end();

    let data = '';

    pythonProcess.stdout.on('data', (chunk) => {
        data += chunk; // Append data from Python script
    });

    pythonProcess.stdout.on('end', () => {
        try {
            const entities = JSON.parse(data); // Parse the JSON result
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            res.json({ entities });
        } catch (error) {
            console.error('Error parsing JSON:', error);
            res.status(500).send({ error: 'Error parsing entity data' });
        }
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error(`Python Error: ${data}`);
        res.status(500).send({ error: 'An error occurred in entity extraction' });
    });

    pythonProcess.on('error', (error) => {
        console.error(`Process Error: ${error.message}`);
        res.status(500).send({ error: 'Failed to start entity extraction process' });
    });

    pythonProcess.on('close', (code) => {
        if (code !== 0) {
            console.error(`Python process exited with code ${code}`);
        }
    });
}

app.get('/user-info', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.user.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Only send requestsRemaining as you don't need to send tier information
        res.json({
            requestsRemaining: user.requestsRemaining
        });
    } catch (error) {
        console.error('Error fetching user info:', error);
        res.status(500).json({ error: 'An error occurred while fetching user info' });
    }
});

app.post('/delete-account', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.user.id;
        
        // Delete the user from the database
        await User.findByIdAndDelete(userId);
        
        // Destroy the session
        req.session.destroy((err) => {
            if (err) {
                console.error('Session destruction error:', err);
                return res.status(500).json({ error: 'Failed to log out' });
            }
            
            res.json({ message: 'Account deleted successfully' });
        });
    } catch (error) {
        console.error('Error deleting account:', error);
        res.status(500).json({ error: 'An error occurred while deleting the account' });
    }
});

app.listen(3000, () => {
    console.log('Server is running');
});