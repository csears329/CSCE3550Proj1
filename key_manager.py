import uuid
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

KEY_STORE = [] # stores keys

def generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537, #Necessary for RSA, idk what it does
        key_size=2048 #key length in bits
    )

    public_key = private_key.public_key() #gets a public key from the private key
    kid = str(uuid.uuid4()) #creates a key id with the creation time and the expiry time (currently 1 hour)
    created_at = datetime.utcnow()
    expires_at = created_at + timedelta(hours=1)

    key_record = {
        "kid": kid,
        "private_key": private_key,
        "public_key": public_key,
        "created_at": created_at,
        "expires_at": expires_at,
        "status": "active"
    }
    KEY_STORE.append(key_record) #appends a new key record to the key store
    return key_record

def generate_expired_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    key_record = {
        "kid": str(uuid.uuid4()),
        "private_key": private_key,
        "public_key": public_key,
        "created_at": datetime.utcnow(),
        "expires_at": datetime.utcnow() - timedelta(hours=1),  # expired
        "status": "expired"
    }
    KEY_STORE.append(key_record)
    return key_record

def is_key_expired(key_record):
    return datetime.utcnow() > key_record["expires_at"]

def serialize_public_key(key_record): #makes the publickey readable to humans
    return key_record["public_key"].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def serialize_private_key(key_record): #makes the private key readable to humans, vulnerability but i need to test
    return key_record["private_key"].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
