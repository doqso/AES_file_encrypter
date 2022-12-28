import time
from Cryptodome.Cipher import AES


def create_16b_object(bytes_obj) -> bytes:
    obj_len = len(bytes_obj)
    remaining_space = 16 - obj_len % 16
    if obj_len % 16 == 0:
        return bytes([*bytes_obj])
    else:
        return bytes([*bytes(remaining_space), *bytes_obj])


def sleep(seconds):
    for i in range(seconds):
        print(i, end=" ")
        time.sleep(1)
    print()


def encrypt(passwd_bytes: bytes, file_name: str):
    KEY = create_16b_object(passwd_bytes)
    print('KEY: ', KEY)
    cipher = AES.new(KEY, AES.MODE_EAX)
    nonce = cipher.nonce
    with open(file_name, "r+b") as f:
        data = f.read()
        cipher_text, tag = cipher.encrypt_and_digest(data)
        f.seek(0)
        f.write(nonce)
        f.write(tag)
        f.write(cipher_text)
    print("Encryption done")


def decrypt(passwd_bytes: bytes, file_name: str):
    with open(file_name, "r+b") as f:
        KEY = create_16b_object(passwd_bytes)
        nonce = f.read(16)
        tag = f.read(16)
        cipher_text = f.read()
        cipher = AES.new(KEY, AES.MODE_EAX, nonce=nonce)
        data = cipher.decrypt(cipher_text)
        try:
            cipher.verify(tag)
            f.seek(0)
            f.write(data)
            print("Decryption done")
        except ValueError:
            print("Key incorrect or message corrupted")


# -------------------------------- Main
if __name__ == "__main__":
    passwd = b'doqso'
    file_name = "cipher_test.exe"
    encrypt(passwd, file_name)
    sleep(2)
    decrypt(passwd, file_name)
