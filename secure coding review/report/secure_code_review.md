## 1. Language & Application
- **Language:** Python
- **Framework:** Flask
- **Application:** Blog login and registration system

## 2. Tools Used
- Manual inspection
- Bandit (static analyzer)
- Safety (dependency scanner)

## 3. Identified Vulnerabilities

| Vulnerability | Description | Status |
|---------------|-------------|--------|
| SQL Injection | Raw queries with user input |  Fixed with parameterized queries |
| Plaintext Passwords | Passwords stored directly |  Fixed using `werkzeug.security` |
| No CSRF Protection | Forms vulnerable to CSRF |  Fixed with Flask-WTF |
| Hardcoded Secrets | `secret_key` in code |  Fixed using `.env` and `os.getenv` |

## 4. Fixes Summary

- Used `check_password_hash` & `generate_password_hash`
-  Used `?` placeholders for SQL injection protection
-  Secret key moved to environment variable using `os.getenv()`
-  CSRF Protection implemented using `Flask-WTF` and `CSRFProtect`

## 5. Before & After Example

** Before:**
```python
cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
```

** After:**
```python
cur.execute("SELECT * FROM users WHERE username = ?", (username,))
```

## 6. Tool Output

**Bandit Output**:
No high severity issues found. Common vulnerabilities like use of `eval`, hardcoded passwords, or insecure hash functions are not present.

**Safety Output**:
All dependencies have been verified against known CVEs and are safe.

## 7. Additional Best Practices

-  Secure cookie flags (`SESSION_COOKIE_SECURE`, `HTTPONLY`, `SAMESITE`)
-  Input validation for username and password
-  Session expiration implemented with `PERMANENT_SESSION_LIFETIME`

