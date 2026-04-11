# Security

Workspace for telecom-related coursework and demos.

## Projects

| Folder | Description |
|--------|-------------|
| [TelecomSecure](TelecomSecure/) | Communication_LTD — Flask app with registration, login, password policy (config file), HMAC+salt storage, forgot-password (SHA-1), and customer form (first name, last name, ID). |
| [TelecomNotSecure](TelecomNotSecure/) | Companion / insecure variant (if present). |

## Quick start (TelecomSecure)

See [TelecomSecure/README.md](TelecomSecure/README.md): virtualenv, `pip install -r requirements.txt`, copy `.env.example` to `.env`, run `python app.py`.

Use a free hosted SQL database (e.g. **Neon PostgreSQL**). Copy the connection string into `DATABASE_URL` in `.env`.

## Local secrets

Do not commit `.env`. The repo `.gitignore` ignores `.venv`, `.env`, and `__pycache__`.
