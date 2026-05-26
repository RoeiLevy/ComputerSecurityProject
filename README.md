# Communication_LTD — Web Security Project

A full-stack web application built with **Python / Flask** and **SQLite**, developed as part of a cyber-security course. The project demonstrates both secure development principles and common web vulnerabilities in a controlled, educational setting.

---

## Project Structure

```
ComputerSecurityProject/
├── TelecomSecure/        ← Secure version (Part A + Part B fixes)
└── TelecomNotSecure/     ← Vulnerable version (Part B demonstrations)
```

| Version | Description |
|---|---|
| **TelecomSecure** | Production-ready implementation with all security controls in place |
| **TelecomNotSecure** | Intentionally vulnerable version used to demonstrate SQLi and XSS attacks |

---

## Part A — Secure Development

| Feature | Implementation |
|---|---|
| User registration | Username, email, and password with full validation |
| Password policy | Enforced via `password_policy.json` (editable by admin) |
| Password storage | HMAC-SHA256 with random salt — never stored in plaintext |
| Password history | Last 3 passwords remembered; reuse is blocked |
| Dictionary check | Common/weak passwords rejected against `common_passwords.txt` |
| Login | Verifies user existence and password; returns clear error messages |
| Account lockout | Account locks for 15 minutes after 3 failed login attempts |
| Change password | Requires current password; enforces full policy on new password |
| Forgot password | Generates a SHA-1 token, sends it by email, used to unlock reset flow |
| System screen | Add customers (first name, last name, ID number); display and search |

### Password Policy (`password_policy.json`)

```json
{
  "min_length": 10,
  "require_uppercase": true,
  "require_lowercase": true,
  "require_digit": true,
  "require_special": true,
  "history_size": 3,
  "max_login_attempts": 3,
  "lockout_minutes": 15
}
```

All values are configurable by the system administrator without touching the code.

---

## Part B — Vulnerability Demonstrations

Two versions of the application are provided, as required:

### B.1 — Stored XSS (Cross-Site Scripting)

**Location:** `TelecomNotSecure` → System screen (Add Customer)

The customer's first and last name are stored in the database without sanitization and rendered without HTML escaping (`Markup()` / `| safe` in the template). Any HTML or JavaScript entered as a name is executed in the browser for every user who visits the page.

**Attack example:**
```
First name: <script>alert('XSS')</script>
```

**Fix (TelecomSecure):** Jinja2 auto-escaping is left enabled. Special characters are automatically encoded (`<` → `&lt;`, `>` → `&gt;`), so scripts are displayed as text, never executed.

---

### B.2 — SQL Injection

**Location:** `TelecomNotSecure` → Register, Login, and System screens

User input is concatenated directly into SQL query strings with no parameterization.

| Route | Vulnerable query | Example attack |
|---|---|---|
| `/register` | `WHERE username = '{username}'` | `' OR '1'='1' --` — blocks all registrations |
| `/register` | `INSERT INTO user VALUES ('{username}', ...)` | Inject extra rows with arbitrary credentials |
| `/login` | `WHERE username = '{username}'` | `' OR '1'='1' LIMIT 1 --` — returns first user |
| `/system` (search) | `WHERE first_name LIKE '%{search}%'` | `' UNION SELECT id,username,email,id FROM user --` — dumps all user credentials into the results |
| `/system` (insert) | `INSERT INTO customer VALUES ('{first_name}', ...)` | Inject arbitrary SQL via any name field |

**Fix (TelecomSecure):** All queries use **SQLAlchemy ORM** or `text()` with **bound parameters**. User input is never interpolated into the SQL string, so injection payloads are treated as literal data.

---

## Getting Started

### Prerequisites

- Python 3.10 or newer
- `pip`

### Setup

```bash
# Clone the repository
git clone https://github.com/RoeiLevy/ComputerSecurityProject.git
cd ComputerSecurityProject

# Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS / Linux

# Install dependencies
pip install -r TelecomSecure/requirements.txt
```

### Run the Secure version

```bash
cd TelecomSecure
copy .env.example .env      # Windows
# cp .env.example .env      # macOS / Linux

# Edit .env — set SECRET_KEY, HMAC_SECRET, and DATABASE_URL
# For local development, SQLite works out of the box:
#   DATABASE_URL=sqlite:///telecom_secure.db

python app.py
# → Open http://127.0.0.1:5000
```

### Run the Vulnerable version

```bash
cd TelecomNotSecure
copy .env.example .env
python app.py
# → Open http://127.0.0.1:5000
```

### Environment variables (`.env`)

| Variable | Description | Example |
|---|---|---|
| `SECRET_KEY` | Flask session secret | any random string |
| `HMAC_SECRET` | Key used for password HMAC | any random string |
| `DATABASE_URL` | SQLAlchemy DB URL | `sqlite:///telecom_secure.db` |
| `SMTP_HOST` | SMTP server for email (optional) | `smtp.gmail.com` |
| `SMTP_PORT` | SMTP port | `587` |
| `SMTP_USER` | SMTP username | your email |
| `SMTP_PASS` | SMTP password | your app password |

> If `SMTP_HOST` is left empty, the SHA-1 reset token is printed to the terminal instead of being emailed — useful for local development.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask, Flask-SQLAlchemy |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Password hashing | HMAC-SHA256 with random salt (secrets module) |
| Reset tokens | SHA-1 of a cryptographically random value |
| Templates | Jinja2 (auto-escaping enabled in secure version) |
| Styling | Custom CSS — no external framework dependencies |

---

## Security Notes

- `.env` files are excluded from version control via `.gitignore` — never commit secrets
- The `TelecomNotSecure` version is provided solely for educational demonstration and must not be deployed to a public server
- Account lockout, password history, and dictionary checks are all driven by `password_policy.json` and require no code changes to adjust
