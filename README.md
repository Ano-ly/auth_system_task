# Anom's User Authentication API

A user authentication system built with Flask, supporting JWT authentication, multi-factor authentication (MFA), role-based access control, and email-based password reset. Includes interactive API documentation via Swagger (OpenAPI).

---

## Features

- User registration and login with JWT tokens
- Multi-factor authentication (MFA) via email OTP
- Password reset via email
- Role-based access control (RBAC)
- Admin role management
- Interactive API documentation (Swagger UI)

---

## Getting Started

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd auth_system_task
```

### 2. Create and Activate a Virtual Environment (Recommended)

```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file in the project root with the following variables:

```env
SECRET_KEY=your_flask_secret_key
JWT_SECRET_KEY=your_jwt_secret_key
DATABASE_URL=sqlite:///auth.db  # Or your preferred SQLAlchemy DB URI
JWT_ACCESS_TOKEN_EXPIRES_SECONDS=3600
JWT_REFRESH_TOKEN_EXPIRES_DAYS=30

MAIL_SERVER=smtp.example.com
MAIL_PORT=2525
MAIL_USE_TLS=True
MAIL_USE_SSL=False
MAIL_USERNAME=your_email_username
MAIL_PASSWORD=your_email_password
MAIL_DEFAULT_SENDER=your_email@example.com
```

> **Note:** For local development, you can use [Mailtrap](https://mailtrap.io/) or similar services for email testing.

### 5. Initialize the Database

The database tables are automatically created on first run. If you want to manually initialize:

```bash
python3 app.py
```

---

## Running the Application

```bash
python3 app.py
```

- The API will be available at: `http://localhost:5000/`
- Swagger UI (API docs): `http://localhost:5000/apidocs`

---

## API Documentation

Interactive API documentation is available via Swagger UI at `/apidocs`.

All endpoints are prefixed with `/api/auth`.

### Authentication Endpoints

- `POST /api/auth/register` — Register a new user
- `POST /api/auth/login` — User login (returns JWT tokens, or triggers MFA if enabled)
- `POST /api/auth/login/mfa-verify` — Verify MFA OTP during login
- `POST /api/auth/token/refresh` — Refresh access token (requires refresh token)

### MFA Endpoints

- `POST /api/auth/mfa/enable` — Enable MFA (requires authentication)
- `POST /api/auth/mfa/verify` — Verify OTP to enable MFA
- `POST /api/auth/mfa/disable` — Disable MFA (requires authentication)

### Password Management

- `POST /api/auth/forgot_password` — Request password reset link
- `POST /api/auth/reset_password/<token>` — Reset password using token

### Role Management (Admin Only)

- `POST /api/auth/manage_roles` — Add or remove roles for a user (requires admin role)

---

## Security

- All protected endpoints require a JWT Bearer token in the `Authorization` header:
  ```
  Authorization: Bearer <your-access-token>
  ```
- Admin endpoints require the user to have the `admin` role.

---

## Development Notes

- The app uses Flask blueprints for modularity (`auth.py`).
- Role-based access is enforced via the `roles_required` decorator (`roles.py`).
- Passwords are securely hashed using bcrypt.
- MFA codes and password reset tokens are time-limited for security.

---

## Troubleshooting

- **Database errors**: Ensure your `DATABASE_URL` is correct and the database is accessible.
- **Email not sending**: Check your SMTP credentials and network access.
- **Swagger UI not loading**: Ensure Flasgger is installed and the app is running.

---

## License

MIT License

---

## Author

Ano-ly

---


