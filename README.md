# BugSentry Auth Service

Central auth service for three MVP applications:

- `dashboard`: subscription, master profile, business account management
- `storefront`: business-facing app that mirrors dashboard login
- `ops_hub`: app for customers, medical stores, and delivery partners

## What this service owns

- email/password registration and login
- Google sign-in
- one shared `users` collection for all apps
- app-wise access via `app_id`
- per-app roles inside `memberships`
- subscription plan on the main user profile

## Request pattern

Every auth request must send an `app_id`.

Examples:

```json
POST /auth/register
{
  "app_id": "dashboard",
  "requested_role": "business_owner",
  "email": "owner@example.com",
  "password": "strongpass123",
  "name": "Owner"
}
```

```json
POST /auth/login
{
  "app_id": "ops_hub",
  "requested_role": "delivery_partner",
  "email": "rider@example.com",
  "password": "strongpass123"
}
```

```json
POST /auth/google
{
  "app_id": "storefront",
  "requested_role": "medical_owner",
  "id_token": "google-id-token-from-frontend"
}
```

## Recommended MVP database

Use MongoDB Atlas.

Why:

- very fast to start for MVP
- works well with flexible user profiles and per-app memberships
- handles burst login traffic with indexing and connection pooling
- easy to connect from Render

## Scale note

For an MVP, 1000 concurrent login requests is realistic if you keep:

- Render web service running with multiple workers
- MongoDB Atlas on a proper shared/dedicated tier
- indexes on `email`, `google_id`, and `memberships.app_id`
- JWT stateless so session reads stay cheap

If you later need stricter logout/session revocation, add Redis for refresh tokens and token blacklist.

## How to Run Locally

You can run this project either natively using Python (recommended for checking and developing the code) or using Docker.

### Option 1: Native Setup (Without Docker)

This is the best way to understand the code and make changes. Ensure you have Python installed (version 3.9+).

**1. Create a Virtual Environment**
Open your terminal or command prompt in the project folder (`BugSentry-Auth`) and run:
```bash
python -m venv venv
```

**2. Activate the Virtual Environment**
- **Windows (Command Prompt):** `venv\Scripts\activate.bat`
- **Windows (PowerShell):** `venv\Scripts\Activate.ps1`
- **Mac/Linux:** `source venv/bin/activate`

**3. Install Dependencies**
```bash
pip install -r requirements.txt
```

**4. Set up Environment Variables**
Copy the `.env.example` file to a new file named `.env`:
- **Windows:** `copy .env.example .env`
- **Mac/Linux:** `cp .env.example .env`

*Note: For the MVP, you will need a running MongoDB database. Update `MONGO_URI` in the `.env` file with your own MongoDB Atlas connection string.*

**5. Run the Application**
Start the FastAPI server:
```bash
python app/main.py
```
*(Alternatively, you can run: `uvicorn app.main:app --reload --port 8001`)*

**6. Check the Running App**
Open your browser and navigate to:
- **API Docs (Swagger UI):** [http://localhost:8001/docs](http://localhost:8001/docs)
- **Health Check:** [http://localhost:8001/health](http://localhost:8001/health)

---

### Option 2: Local Docker Run

If you have Docker installed and prefer not to install Python locally:

**1. Set up Environment Variables**
Copy `.env.example` to `.env` as shown above.

**2. Build and Start the Containers**
```bash
docker compose up --build
```

**3. Access the APIs**
- API docs: `http://localhost:8001/docs`
- Health: `http://localhost:8001/health`

## Backend integration rules

- every app must call the same auth backend
- every login/register/google request must include `app_id`
- use `dashboard` for subscription app
- use `storefront` for business mirror app
- use `ops_hub` for customer, medical owner, or delivery partner flows

## Deployment Setup

- keep Render service as Docker runtime
- set `MONGO_URI` to MongoDB Atlas, not local Mongo
- ensure `JWT_SECRET`, `GOOGLE_CLIENT_ID`, and `CORS_ORIGINS` are securely set.  
 
#   S a n j e e v a n i - A u t h  
 #   B u g S e n t r y - A u t h  