import os
import random
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import jwt
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

app = Flask(__name__)

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "FRONTEND_URL",
        "http://localhost:8080,http://127.0.0.1:8080,http://localhost:5173",
    ).split(",")
    if origin.strip()
]

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": allowed_origins,
        }
    },
)

JWT_SECRET = os.getenv("JWT_SECRET", "change-this-secret")
JWT_ALGORITHM = "HS256"
OTP_EXPIRY_MINUTES = int(os.getenv("OTP_EXPIRY_MINUTES", "10"))
OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", "5"))

# Replace these in-memory stores with your database models in production.
pending_registrations: dict[str, dict[str, Any]] = {}
users: dict[str, dict[str, Any]] = {}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def generate_otp() -> str:
    return f"{random.randint(100000, 999999)}"


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user.get("role", "student"),
        "isEmailVerified": user.get("is_email_verified", False),
    }


def create_token(user: dict[str, Any]) -> str:
    payload = {
        "sub": user["id"],
        "email": user["email"],
        "role": user.get("role", "student"),
        "exp": now_utc() + timedelta(days=7),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def build_otp_email_html(name: str, otp: str) -> str:
    display_name = name.strip() or "there"
    spaced_otp = " ".join(otp)

    return f"""\
<!doctype html>
<html>
  <body style="margin:0;padding:0;background:#f3f4f6;font-family:Arial,Helvetica,sans-serif;color:#0b1f3a;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f3f4f6;margin:0;padding:0;">
      <tr>
        <td align="center" style="padding:24px 12px;">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:612px;background:#ffffff;border-radius:10px;">
            <tr>
              <td style="padding:36px 36px 30px 36px;">
                <h1 style="margin:0 0 24px 0;font-size:24px;line-height:32px;font-weight:700;color:#071a36;">
                  Verify your email
                </h1>

                <p style="margin:0 0 18px 0;font-size:16px;line-height:24px;color:#10284a;">
                  Hi <strong>{display_name}</strong>,
                </p>

                <p style="margin:0 0 36px 0;font-size:16px;line-height:24px;color:#10284a;">
                  Use the code below to verify your account. It expires in <strong>{OTP_EXPIRY_MINUTES} minutes.</strong>
                </p>

                <table role="presentation" cellspacing="0" cellpadding="0" align="center" style="margin:0 auto 36px auto;">
                  <tr>
                    <td style="background:#eef5ff;border-radius:10px;padding:26px 34px;text-align:center;">
                      <span style="font-size:48px;line-height:56px;font-weight:700;letter-spacing:12px;color:#2563eb;font-family:Arial,Helvetica,sans-serif;">
                        {spaced_otp}
                      </span>
                    </td>
                  </tr>
                </table>

                <p style="margin:0 0 30px 0;font-size:15px;line-height:23px;color:#7f8fb4;">
                  If you did not create an account, ignore this email. Do not share this code with anyone.
                </p>

                <div style="height:1px;background:#dbe3ef;margin:0 0 28px 0;"></div>

                <p style="margin:0;font-size:14px;line-height:20px;color:#b7c4d8;">
                  Answer Sheet Evaluator
                </p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
"""


def send_otp_email(email: str, otp: str, name: str) -> None:
    zoho_email = os.getenv("ZOHO_EMAIL", "").strip()
    zoho_app_password = os.getenv("ZOHO_APP_PASSWORD", "").strip().replace(" ", "")
    smtp_hosts = [
        host.strip()
        for host in os.getenv("SMTP_HOSTS", os.getenv("SMTP_HOST", "smtp.zoho.com")).split(",")
        if host.strip()
    ]
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_security = os.getenv("SMTP_SECURITY", "starttls").strip().lower()

    if not zoho_email or not zoho_app_password:
        raise RuntimeError("ZOHO_EMAIL and ZOHO_APP_PASSWORD are required")

    message = MIMEMultipart("alternative")
    message["Subject"] = "Verify your training account"
    message["From"] = zoho_email
    message["To"] = email
    message.attach(
        MIMEText(
            f"Hi {name or 'there'}, your verification code is {otp}. "
            f"It expires in {OTP_EXPIRY_MINUTES} minutes.",
            "plain",
        )
    )
    message.attach(MIMEText(build_otp_email_html(name, otp), "html"))

    errors: list[str] = []

    for smtp_host in smtp_hosts:
        try:
            if smtp_security == "ssl":
                server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=20)
            else:
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=20)

            with server:
                if smtp_security != "ssl":
                    server.starttls()
                server.login(zoho_email, zoho_app_password)
                server.sendmail(zoho_email, [email], message.as_string())
                return
        except smtplib.SMTPAuthenticationError as exc:
            errors.append(f"{smtp_host}: authentication failed ({exc.smtp_code})")
        except Exception as exc:
            errors.append(f"{smtp_host}: {exc}")

    raise RuntimeError(
        "Zoho SMTP login failed. Tried "
        + ", ".join(errors)
        + ". Regenerate the Zoho app password and confirm the correct Zoho data-center SMTP host."
    )


@app.get("/api/health")
def health():
    return jsonify({"success": True, "message": "Backend is running"})


@app.post("/api/auth/register/request-otp")
def request_register_otp():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    email = normalize_email(str(data.get("email", "")))
    password = str(data.get("password", ""))
    role = str(data.get("role", "student") or "student")

    if not name or not email or not password:
        return jsonify({"success": False, "message": "All fields are required"}), 400

    if "@" not in email or "." not in email:
        return jsonify({"success": False, "message": "Please enter a valid email"}), 400

    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters"}), 400

    if email in users:
        return jsonify({"success": False, "message": "Email is already registered"}), 409

    otp = generate_otp()
    pending_registrations[email] = {
        "name": name,
        "email": email,
        "password_hash": generate_password_hash(password),
        "role": role,
        "otp_hash": generate_password_hash(otp),
        "otp_expires_at": now_utc() + timedelta(minutes=OTP_EXPIRY_MINUTES),
        "attempts": 0,
    }

    try:
        send_otp_email(email, otp, name)
    except Exception as exc:
        pending_registrations.pop(email, None)
        return jsonify({"success": False, "message": str(exc)}), 500

    return jsonify({"success": True, "message": "OTP sent to your email"})


@app.post("/api/auth/register/verify-otp")
def verify_register_otp():
    data = request.get_json(silent=True) or {}
    email = normalize_email(str(data.get("email", "")))
    otp = str(data.get("otp", "")).strip()

    pending = pending_registrations.get(email)
    if not pending:
        return jsonify({"success": False, "message": "Please request a new OTP"}), 400

    if pending["otp_expires_at"] < now_utc():
        pending_registrations.pop(email, None)
        return jsonify({"success": False, "message": "OTP expired. Please request a new one"}), 400

    if pending["attempts"] >= OTP_MAX_ATTEMPTS:
        pending_registrations.pop(email, None)
        return jsonify({"success": False, "message": "Too many attempts. Please request a new OTP"}), 429

    if not check_password_hash(pending["otp_hash"], otp):
        pending["attempts"] += 1
        return jsonify({"success": False, "message": "Invalid OTP"}), 400

    user_id = str(len(users) + 1)
    user = {
        "id": user_id,
        "name": pending["name"],
        "email": pending["email"],
        "password_hash": pending["password_hash"],
        "role": pending["role"],
        "is_email_verified": True,
        "created_at": now_utc().isoformat(),
    }
    users[email] = user
    pending_registrations.pop(email, None)

    token = create_token(user)
    return jsonify(
        {
            "success": True,
            "message": "Email verified successfully",
            "token": token,
            "user": public_user(user),
        }
    )


@app.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    email = normalize_email(str(data.get("email", "")))
    password = str(data.get("password", ""))

    user = users.get(email)
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"success": False, "message": "Invalid email or password"}), 401

    token = create_token(user)
    return jsonify({"success": True, "token": token, "user": public_user(user)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
