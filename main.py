from datetime import datetime
from fastapi import FastAPI, Request
from key_manager import KEY_STORE, generate_key, generate_expired_key, is_key_expired
from jwt_manager import sign_jwt
import base64

app = FastAPI()

#create keys for testing
for _ in range(4):
    generate_key()
generate_expired_key()

def convert_to_jwk(key_record):
    public_numbers = key_record["public_key"].public_numbers()
    n = base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode("utf-8")
    e = base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")).rstrip(b"=").decode("utf-8")
    return {
        "kty": "RSA", # key type
        "use": "sig", # being used for signature
        "alg": "RS256", #the algorithm
        "kid": key_record["kid"], #key id
        "n": n, #one of the numbers used in generating a key
        "e": e #one of the numbers used in generating a key
    }

@app.get("/jwks")
def get_jwks():
    keys = [convert_to_jwk(k) for k in KEY_STORE if not is_key_expired(k)]
    return {"keys": keys}

@app.get("/.well-known/jwks.json")
def get_jwks_well_known():
    return get_jwks()

@app.post("/auth")
def auth(request: Request):
    use_expired = "expired" in request.query_params
    #for expired
    if use_expired:
        key = next((k for k in reversed(KEY_STORE) if is_key_expired(k)), None)
        if not key:
            return {"error": "No suitable key available"}

        now_ts = int(datetime.utcnow().timestamp())
        exp_ts = now_ts - 86400 # 1 day in the past
        iat_ts = exp_ts - 90000
        print("EXPIRED MODE now_ts=", now_ts, "exp_ts=", exp_ts, "iat_ts=", iat_ts)

        token = sign_jwt(key, iat_ts=iat_ts, exp_ts=exp_ts)
        return {"token": token}

    #for active
    key = next((k for k in reversed(KEY_STORE) if not is_key_expired(k)), None)
    if not key:
        return {"error": "No suitable key available"}

    token = sign_jwt(key, expire_seconds=3600)
    return {"token": token}

@app.get("/auth")
def auth_get(request: Request):
    return auth(request)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)

