import jwt
from datetime import datetime, timedelta

def sign_jwt(key_record, subject="user123", expire_seconds=3600, *, iat_ts=None, exp_ts=None):
    now = datetime.utcnow()

    if exp_ts is None:
        exp = now + timedelta(seconds=expire_seconds)
        exp_ts = int(exp.timestamp())

    if iat_ts is None:
        iat_ts = int(now.timestamp())

    payload = {
        "sub": subject,
        "iat": int(iat_ts),
        "exp": int(exp_ts),
    }

    return jwt.encode(
        payload,
        key_record["private_key"],
        algorithm="RS256",
        headers={"kid": key_record["kid"]},
    )