# SalonBook — Server (single-file JS version)

This is the SalonBook backend written in the same style as the HireLoop
example you shared: one `index.js`, plain JavaScript (ES modules),
Express, the native MongoDB driver, `verifyToken` / role middlewares
that look up the Better Auth session, and Stripe.

It is a drop-in alternative to the TypeScript server in `../server`.
Use **one** of them as your server repo — do not deploy both.

- **Live Website:** _TODO — add the deployed client URL_
- **Client Repository:** _TODO — add the client repo URL_
- **Server Repository:** _TODO — add this repo URL_

## Features

- Better Auth at `/api/auth/*`: email/password + Google, with extra
  user fields `role` (`customer` / `admin`), `isBlocked`, `phone`
- `verifyToken` looks up the session token in the `session` collection,
  loads the fresh user from the `user` collection, and blocks blocked
  users. `verifyCustomer` and `verifyAdmin` run after it — same pattern
  as `verifySeeker` / `verifyRecruiter` / `verifyAdmin` in HireLoop
- Services: public browse with search, category filter, price sort;
  admin create / update / delete / activate-deactivate
- Appointments: customer booking (active service, future date, valid
  time slot, no duplicate active slot), admin confirm, customer/admin
  cancel with the correct rules, customers only ever see their own
- Users: admin list / view / change role / block-unblock; profile
  update for name, image, phone only
- Dashboard stats for admin and customer
- Image upload to ImgBB (`POST /upload`, multipart field `image`)
- Stripe Checkout for confirmed + unpaid appointments, plus a
  **verified webhook** at `POST /api/webhooks/stripe` (also `/webhooks/stripe`)

### Important difference from the HireLoop payment example

In HireLoop, `/payments/checkout-verify` marks the user premium after
checking the session. SalonBook's assignment says the opposite:
**payment status must be updated only after a verified Stripe webhook
event.** So in this server:

- `POST /payments/checkout/:appointmentId` creates the Checkout session
- `POST /payments/checkout-verify` only *reads* the session status
- `POST /webhooks/stripe` verifies the Stripe signature, and only then
  sets the appointment to `paid` and inserts the transaction

Do not remove the webhook, or you will lose marks.

## Technology Stack

Node.js, Express.js, MongoDB (native driver), Better Auth, Stripe,
ImgBB, Multer, CORS, dotenv. No TypeScript, no Mongoose — both are
optional in the assignment.

## How to Run Locally

```bash
cd server   # workspace copy folder name: server-js
npm install
cp .env.example .env
# fill in .env — never commit real keys
npm run dev     # nodemon, http://localhost:5000
# or
npm start       # node index.js
```

Services are stored in the database (`services` collection), not in
code. Add services from the admin dashboard (Manage Services → Add
Service). On first start the server creates the admin account from
`ADMIN_EMAIL` / `ADMIN_PASSWORD` (only if that email does not exist).

## Environment Variables (names only)

| Variable | Purpose |
| --- | --- |
| `PORT` | Server port, default `5000` |
| `MONGODB_URI` | MongoDB connection string (recommended) |
| `DB_USER` / `DB_PASSWORD` | Alternative, HireLoop style, used if `MONGODB_URI` is empty |
| `BETTER_AUTH_SECRET` | Better Auth secret |
| `JWT_SECRET` | Secret for signing/verifying JWT API tokens (long random text) |
| `BETTER_AUTH_URL` | Public URL of this server |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google sign-in |
| `STRIPE_SECRET_KEY` | Stripe secret key (test mode) |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret |
| `IMGBB_API_KEY` | Image uploads |
| `CLIENT_URL` | Client origin, e.g. `http://localhost:3000` |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` / `ADMIN_NAME` | First admin account, seeded on startup |

## API Overview

> Every API route below also answers under `/api/...` (e.g. `/api/services`) — the SalonBook client uses the `/api/...` paths. Auth accepts the Better Auth cookie session (what the client sends), a Better Auth session token, or a JWT in the `Authorization: Bearer <token>` header. Get a JWT from `POST /api/jwt` after sign-in; `verifyToken` verifies it with `jwt.verify` (jsonwebtoken) and then checks role/blocked status from the database on every protected route.


| Method | Route | Access |
| --- | --- | --- |
| GET | `/` , `/health` | Public |
| GET | `/services?search=&category=&sort=price_asc\|price_desc` | Public (active only; admin `?all=true`) |
| GET | `/services/:id` | Public |
| POST / PUT / DELETE | `/services`, `/services/:id` | Admin |
| PATCH | `/services/:id/status` | Admin |
| POST | `/upload` | Logged-in user |
| POST | `/appointments` | Customer |
| GET | `/appointments`, `/appointments/my`, `/appointments/:id` | Owner or admin |
| PATCH | `/appointments/:id/confirm` | Admin (pending only) |
| PATCH | `/appointments/:id/cancel` | Owner (pending) or admin |
| GET | `/users`, `/users/:id` | Admin |
| PATCH | `/users/:id/role`, `/users/:id/block` | Admin |
| PATCH | `/users/me/profile` | Logged-in user |
| GET | `/dashboard/admin`, `/dashboard/customer` | Admin / Customer |
| POST | `/payments/checkout/:appointmentId` | Customer (own, confirmed + unpaid) |
| POST | `/payments/checkout-verify` | Public check (does not mark paid) |
| POST | `/webhooks/stripe` | Stripe (signature-verified) |
| GET | `/transactions`, `/transactions/my` | Admin / Customer |

Auth endpoints are served by Better Auth under `/api/auth/*`. Send the
session token as `Authorization: Bearer <token>` on protected routes.

## Stripe Webhook (local testing)

```bash
stripe listen --forward-to localhost:5000/api/webhooks/stripe
# copy the webhook signing secret into STRIPE_WEBHOOK_SECRET
```

Then book as a customer, confirm as admin, pay with test card
`4242 4242 4242 4242`, and check the appointment becomes `paid` and a
transaction appears.

## Collections

`user`, `session`, `account`, `verification` (Better Auth),
`services`, `appointments`, `transactions` — in database `salonbookdb`.
