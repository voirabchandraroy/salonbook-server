import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import { MongoClient, ObjectId } from 'mongodb';
import Stripe from 'stripe';
import multer from 'multer';
import { betterAuth } from 'better-auth';
import { mongodbAdapter } from 'better-auth/adapters/mongodb';
import { toNodeHandler, fromNodeHeaders } from 'better-auth/node';
import jwt from 'jsonwebtoken';

// jwt secret from .env, used for signing and verifying tokens
const JWT_SECRET = process.env.JWT_SECRET || process.env.BETTER_AUTH_SECRET || 'salonbook-dev-jwt-secret-change-me';
if (!process.env.JWT_SECRET && !process.env.BETTER_AUTH_SECRET) {
    console.warn('[warning] JWT_SECRET is empty. Add JWT_SECRET in your .env file (a long random text), otherwise JWT tokens will not be secure.');
}

// stripe secret key from .env, placeholder just keeps the server running without it
if (!process.env.STRIPE_SECRET_KEY) {
    console.warn('[warning] STRIPE_SECRET_KEY is empty. Add it in your .env file, otherwise Stripe payments will not work.');
}
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder_not_a_real_key');

const app = express();
const port = process.env.PORT || 5000;

// stripe webhook route is added before express.json() below, it needs the raw body

// mongodb connection string from .env
const uri = process.env.MONGODB_URI ||
  (process.env.DB_USER && process.env.DB_PASSWORD
    ? `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.vyznij5.mongodb.net/`
    : '');

if (!uri) {
    console.error('[error] MONGODB_URI is empty. Add MONGODB_URI (or DB_USER / DB_PASSWORD) in your .env file, then restart. See .env.example.');
}

const client = new MongoClient(uri || 'mongodb://127.0.0.1:27017');

const myLogger = (req, res, next) => {
    console.log('now hitting api', req.url, req.headers);
    next();
};

export async function connectToMongoDB() {
    try {
        await client.connect();
        console.log("You successfully connected to MongoDB!");
        return client;
    } catch (err) {
        console.error('[error] MongoDB connection failed:', err.message);
        console.error('[error] Check MONGODB_URI in .env (Atlas: Database Access user + Network Access 0.0.0.0/0), then restart.');
        process.exit(1);
    }
}

const connectedClient = await connectToMongoDB();
const database = connectedClient.db("salonbookdb");
const users = database.collection("user");
const sessions = database.collection("session");
const services = database.collection("services");
const appointments = database.collection("appointments");
const transactions = database.collection("transactions");

// better auth setup, extra user fields: role, isBlocked, phone
// admin is created from .env below, not from public sign up
// live client and server are on different domains, so the login cookie
// needs SameSite=None on https (local http keeps lax)
const isLiveHttps = (process.env.BETTER_AUTH_URL || '').startsWith('https://');
const auth = betterAuth({
    secret: process.env.BETTER_AUTH_SECRET || "dev-only-secret-change-me",
    baseURL: process.env.BETTER_AUTH_URL || `http://localhost:${port}`,
    trustedOrigins: [process.env.CLIENT_URL || 'http://localhost:3000', process.env.BETTER_AUTH_URL || `http://localhost:${port}`],
    advanced: {
        defaultCookieAttributes: isLiveHttps
            ? { sameSite: 'none', secure: true }
            : { sameSite: 'lax', secure: false },
    },
    database: mongodbAdapter(database),
    emailAndPassword: {
        enabled: true,
        minPasswordLength: 6,
    },
    socialProviders: (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) ? {
        google: {
            clientId: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        }
    } : {},
    user: {
        additionalFields: {
            role: { type: "string", defaultValue: "customer", required: false },
            isBlocked: { type: "boolean", defaultValue: false, required: false },
            phone: { type: "string", required: false },
        }
    },
});

// stripe webhook, must be before express.json()
// payment status becomes paid only from here, after verification
app.post(['/webhooks/stripe', '/api/webhooks/stripe'], express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.log('Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const appointmentId = session.metadata?.appointmentId;
        const customerId = session.metadata?.customerId;

        if (session.payment_status === 'paid' && appointmentId) {
            // skip if this session is already saved
            const existing = await transactions.findOne({ stripeSessionId: session.id });
            if (!existing) {
                // save transaction
                await transactions.insertOne({
                    appointmentId,
                    customerId,
                    amount: session.amount_total ? session.amount_total / 100 : 0,
                    currency: session.currency,
                    stripeSessionId: session.id,
                    status: 'paid',
                    createdAt: new Date(),
                });
                // now mark the appointment as paid
                await appointments.updateOne(
                    { _id: new ObjectId(appointmentId) },
                    { $set: { paymentStatus: 'paid' } }
                );
            }
        }
    }

    if (event.type === 'checkout.session.async_payment_failed' || event.type === 'payment_intent.payment_failed') {
        const session = event.data.object;
        if (session.id) {
            await transactions.insertOne({
                appointmentId: session.metadata?.appointmentId || null,
                customerId: session.metadata?.customerId || null,
                amount: session.amount_total ? session.amount_total / 100 : 0,
                currency: session.currency || 'usd',
                stripeSessionId: session.id,
                status: 'failed',
                createdAt: new Date(),
            }).catch(() => {});
        }
    }

    res.json({ received: true });
});

// middleware
app.use(express.json());
app.use(cors({
    origin: [process.env.CLIENT_URL || 'http://localhost:3000', 'http://localhost:3000'],
    credentials: true,
}));

// Better Auth routes: /api/auth/*
app.all('/api/auth/*', toNodeHandler(auth));

app.get('/', (req, res) => {
    res.send('salon book is running');
});

app.get(['/health', '/api/health'], (req, res) => {
    res.send({ success: true, message: 'SalonBook server is running' });
});

// auth middlewares
// verifyToken checks the jwt from the Authorization header, then loads
// the user from db so role and blocked status are checked on the server.
// it also accepts the better auth session token and the cookie session.
function createJwtToken(user) {
    return jwt.sign(
        { sub: user._id.toString(), email: user.email, role: user.role },
        JWT_SECRET,
        { expiresIn: '7d' }
    );
}

async function getUserFromRequest(req) {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        if (token) {
            // first try jwt
            try {
                const decoded = jwt.verify(token, JWT_SECRET);
                if (decoded?.sub && ObjectId.isValid(decoded.sub)) {
                    const user = await users.findOne({ _id: new ObjectId(decoded.sub) });
                    if (user) return user;
                }
            } catch (err) {
                // not a jwt, try session token below
            }
            // better auth session token
            const session = await sessions.findOne({ token });
            if (session && !(session.expiresAt && new Date(session.expiresAt) < new Date())) {
                const user = await users.findOne({ _id: new ObjectId(session.userId) });
                if (user) return user;
            }
        }
    }
    try {
        const session = await auth.api.getSession({ headers: fromNodeHeaders(req.headers) });
        if (session?.user?.id) {
            let user = null;
            if (ObjectId.isValid(session.user.id)) {
                user = await users.findOne({ _id: new ObjectId(session.user.id) });
            }
            if (!user) user = await users.findOne({ _id: session.user.id });
            if (!user && session.user.email) user = await users.findOne({ email: session.user.email });
            if (user) return user;
        }
    } catch (err) {
        // no cookie session
    }
    return null;
}

const verifyToken = async (req, res, next) => {
    const user = await getUserFromRequest(req);
    if (!user) {
        res.status(401).send({ message: 'Unauthorized' });
        return;
    }
    if (user.isBlocked) {
        res.status(403).send({ message: 'Your account is blocked' });
        return;
    }
    req.user = user;
    next();
};

// must call these middlewares after verifyToken
const verifyCustomer = async (req, res, next) => {
    if (req.user.role !== 'customer') {
        res.status(403).send({ message: 'Forbidden' });
        return;
    }
    next();
};

const verifyAdmin = async (req, res, next) => {
    if (req.user.role !== 'admin') {
        res.status(403).send({ message: 'Forbidden' });
        return;
    }
    next();
};

// get a jwt after login, client sends it as Authorization: Bearer <token>
app.post(['/jwt', '/api/jwt'], verifyToken, (req, res) => {
    const token = createJwtToken(req.user);
    res.send({ token });
});

// remove password before sending user to client
const toPublicUser = (user) => {
    if (!user) return user;
    const { password, ...safe } = user;
    return safe;
};

const TIME_SLOTS = ['09:00', '10:00', '11:00', '12:00', '14:00', '15:00', '16:00', '17:00', '18:00'];

// users related apis
app.get(['/users', '/api/users'], verifyToken, verifyAdmin, async (req, res) => {
    const cursor = users.find({});
    const result = await cursor.toArray();
    res.send(result.map(toPublicUser));
});

app.get(['/users/:id', '/api/users/:id'], verifyToken, verifyAdmin, async (req, res) => {
    const id = req.params.id;
    const query = { _id: new ObjectId(id) };
    const result = await users.findOne(query);
    res.send(toPublicUser(result));
});

// admin can change a role from the admin panel (never from profile update)
app.patch(['/users/:id/role', '/api/users/:id/role'], verifyToken, verifyAdmin, async (req, res) => {
    const id = req.params.id;
    const query = { _id: new ObjectId(id) };
    const updatedDoc = {
        $set: {
            role: req.body.role,
        }
    };
    const result = await users.updateOne(query, updatedDoc);
    res.send(result);
});

// admin block / unblock a customer
app.patch(['/users/:id/block', '/api/users/:id/block'], verifyToken, verifyAdmin, async (req, res) => {
    const id = req.params.id;
    if (req.user._id.toString() === id) {
        return res.status(400).send({ message: 'You cannot block yourself' });
    }
    const target = await users.findOne({ _id: new ObjectId(id) });
    if (!target) return res.status(404).send({ message: 'User not found' });
    if (target.role === 'admin') {
        return res.status(403).send({ message: 'You cannot block an admin' });
    }
    const isBlocked = typeof req.body.isBlocked === 'boolean' ? req.body.isBlocked : !target.isBlocked;
    const result = await users.updateOne(
        { _id: new ObjectId(id) },
        { $set: { isBlocked } }
    );
    res.send({ ...result, isBlocked });
});

// logged-in user updates own profile: name, image, phone only
// role and isBlocked can never be changed from here
app.patch(['/users/me/profile', '/api/users/me/profile'], verifyToken, async (req, res) => {
    if (req.body.role !== undefined || req.body.isBlocked !== undefined) {
        return res.status(403).send({ message: 'You cannot change your role or blocked status' });
    }
    const updatedDoc = { $set: {} };
    if (req.body.name) updatedDoc.$set.name = req.body.name;
    if (req.body.image !== undefined) updatedDoc.$set.image = req.body.image;
    if (req.body.phone !== undefined) updatedDoc.$set.phone = req.body.phone;

    const result = await users.updateOne(
        { _id: new ObjectId(req.user._id) },
        updatedDoc
    );
    res.send(result);
});

// services related apis
app.get(['/services', '/api/services'], async (req, res) => {
    const query = {};
    // public page shows only active services.
    // admin can pass ?all=true (checked below with a token if present)
    let showAll = false;
    if (req.query.all === 'true') {
        const user = await getUserFromRequest(req);
        if (user && user.role === 'admin' && !user.isBlocked) showAll = true;
    }
    if (!showAll) {
        query.status = 'active';
    }

    if (req.query) {
        if (req.query.category) {
            query.category = req.query.category;
        }
        if (req.query.search) {
            query.$or = [
                { serviceName: { $regex: req.query.search, $options: 'i' } },
                { category: { $regex: req.query.search, $options: 'i' } },
                { description: { $regex: req.query.search, $options: 'i' } }
            ];
        }
    }

    let cursor = services.find(query);
    if (req.query.sort === 'price_asc') {
        cursor = cursor.sort({ price: 1 });
    } else if (req.query.sort === 'price_desc') {
        cursor = cursor.sort({ price: -1 });
    }
    const result = await cursor.toArray();
    res.send(result);
});

app.get(['/services/:id', '/api/services/:id'], async (req, res) => {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) {
        return res.status(404).send({ message: 'Service not found' });
    }
    const query = { _id: new ObjectId(id) };
    const result = await services.findOne(query);
    if (!result) {
        return res.status(404).send({ message: 'Service not found' });
    }
    res.send(result);
});

app.post(['/services', '/api/services'], verifyToken, verifyAdmin, async (req, res) => {
    const { serviceName, category, description, price, duration, image, status } = req.body;
    if (!serviceName || !category || !description || !image) {
        return res.status(400).send({ message: 'serviceName, category, description and image are required' });
    }
    if (!(Number(price) > 0) || !(Number(duration) > 0)) {
        return res.status(400).send({ message: 'Price and duration must be positive numbers' });
    }
    const service = {
        serviceName,
        category,
        description,
        price: Number(price),
        duration: Number(duration),
        image,
        status: status === 'inactive' ? 'inactive' : 'active',
        createdAt: new Date(),
    };
    const result = await services.insertOne(service);
    res.send(result);
});

app.put(['/services/:id', '/api/services/:id'], verifyToken, verifyAdmin, async (req, res) => {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(404).send({ message: 'Service not found' });
    const { serviceName, category, description, price, duration, image, status } = req.body;
    if (price !== undefined && !(Number(price) > 0)) {
        return res.status(400).send({ message: 'Price must be a positive number' });
    }
    if (duration !== undefined && !(Number(duration) > 0)) {
        return res.status(400).send({ message: 'Duration must be a positive number' });
    }
    const updatedDoc = {
        $set: {
            ...(serviceName && { serviceName }),
            ...(category && { category }),
            ...(description && { description }),
            ...(price !== undefined && { price: Number(price) }),
            ...(duration !== undefined && { duration: Number(duration) }),
            ...(image && { image }),
            ...(status && { status }),
        }
    };
    const result = await services.updateOne({ _id: new ObjectId(id) }, updatedDoc);
    res.send(result);
});

app.patch(['/services/:id/status', '/api/services/:id/status'], verifyToken, verifyAdmin, async (req, res) => {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(404).send({ message: 'Service not found' });
    const status = req.body.status === 'inactive' ? 'inactive' : 'active';
    const result = await services.updateOne(
        { _id: new ObjectId(id) },
        { $set: { status } }
    );
    res.send(result);
});

// same status update, client admin toggle uses this one
app.patch(['/services/:id', '/api/services/:id'], verifyToken, verifyAdmin, async (req, res) => {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(404).send({ message: 'Service not found' });
    if (req.body.status !== 'active' && req.body.status !== 'inactive') {
        return res.status(400).send({ message: 'Status must be active or inactive' });
    }
    const result = await services.updateOne(
        { _id: new ObjectId(id) },
        { $set: { status: req.body.status } }
    );
    res.send(result);
});

app.delete(['/services/:id', '/api/services/:id'], verifyToken, verifyAdmin, async (req, res) => {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(404).send({ message: 'Service not found' });
    const query = { _id: new ObjectId(id) };
    const result = await services.deleteOne(query);
    res.send(result);
});


app.listen(port, () => {
    console.log(`salon book is running on port ${port}`);
});

export default app;
