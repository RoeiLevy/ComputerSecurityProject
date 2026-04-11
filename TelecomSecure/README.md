# TelecomSecure

Simple secure web app for Communication_LTD.

## Free cloud relational DB

Recommended: **Neon PostgreSQL** (free tier).  
Create DB and copy connection string into `.env`.

## Run

1. `python3 -m venv .venv`
2. `source .venv/bin/activate`
3. `pip install -r requirements.txt`
4. `cp .env.example .env` and fill values
5. `python app.py`

Open `http://127.0.0.1:5000`

## Notes

- Password policy is in `password_policy.json`
- Password saved as `HMAC + Salt`
- Forgot password reset value is SHA-1 and sent by email (or printed in console in dev mode)

