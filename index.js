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


app.listen(port, () => {
    console.log(`salon book is running on port ${port}`);
});

export default app;
