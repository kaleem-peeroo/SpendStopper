import os

from encrypt import encrypt_file, decrypt_file

s_password = os.getenv("PASSWORD")
if not s_password:
    raise ValueError(
        "PASSWORD env hasn't been set. Set using `EXPORT PASSWORD='password_here'` before running this script."
    )

if not os.path.exists("./data/data_sha256.csv"):
    print("Encrypting ./data/data.csv to ./data/data_sha256.csv")
    encrypt_file("./data/data.csv", "./data/data_sha256.csv", s_password)

if not os.path.exists("./data/data.csv"):
    print("Decrypting ./data/data_sh256.csv to ./data/data.csv")
    decrypt_file("./data/data_sha256.csv", "./data/data.csv", s_password)
