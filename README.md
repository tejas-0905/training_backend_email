# Training OTP Backend

This backend provides email OTP verification for signup.

## Local setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python app.py
```

Put your real Zoho app password in `.env` locally and in Render environment
variables for production. Do not put the real password in frontend code.

## Endpoints

- `POST /api/auth/register/request-otp`
- `POST /api/auth/register/verify-otp`
- `POST /api/auth/login`
- `GET /api/health`

The current sample uses in-memory storage. Connect `pending_registrations` and
`users` to your real database before production deployment.
