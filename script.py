import time
from Cryptodome.Cipher import AES


def get_16b_text(text: bytes) -> bytes:
    text_module = len(text) % 16
    if text_module != 0:
        remaining_spaces = 16 - text_module
        return bytes([*bytes(remaining_spaces), *text])
    return text


def sleep(seconds):
    for i in range(seconds):
        print(i, end=" ")
        time.sleep(1)
    print()


def encrypt(passwd_bytes: bytes, file_name: str):
    key = get_16b_text(passwd_bytes)
    cipher = AES.new(key, AES.MODE_EAX)
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
        key = get_16b_text(passwd_bytes)
        nonce = f.read(16)
        tag = f.read(16)
        cipher_text = f.read()
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
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
    passwd = b'my_password'
    file_name = "file_to_encrypt.exe"
    encrypt(passwd, file_name)
    sleep(2)
    decrypt(passwd, file_name)
