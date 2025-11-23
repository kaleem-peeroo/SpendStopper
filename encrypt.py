from cryptography.fernet import Fernet
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def get_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt_file(input_file: str = "", output_file: str = "", password: str = ""):
    if input_file == "" or input_file is None:
        raise ValueError("Empty input file")

    if output_file == "" or output_file is None:
        raise ValueError("Empty output file")

    if password == "" or password is None:
        raise ValueError("Empty password")

    salt = os.urandom(16)
    key = get_key_from_password(password, salt)
    fernet = Fernet(key)

    with open(input_file, "rb") as f:
        data = f.read()
    encrypted = fernet.encrypt(data)

    with open(output_file, "wb") as f:
        f.write(salt + encrypted)  # save salt first


def decrypt_file(encrypted_file, output_file, password):
    if encrypted_file == "" or encrypted_file is None:
        raise ValueError("Empty input file")

    if output_file == "" or output_file is None:
        raise ValueError("Empty output file")

    if password == "" or password is None:
        raise ValueError("Empty password")
    with open(encrypted_file, "rb") as f:
        salt = f.read(16)
        encrypted_data = f.read()

    key = get_key_from_password(password, salt)
    fernet = Fernet(key)

    decrypted = fernet.decrypt(encrypted_data)
    with open(output_file, "wb") as f:
        f.write(decrypted)
