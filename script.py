import time
from Cryptodome.Cipher import AES


def get_16bytes_str(text: str) -> bytes:
    text_module = len(text) % 16
    output = bytes(text, "utf-8")
    if text_module != 0:
        remaining_spaces = 16 - text_module
        return bytes([*bytes(remaining_spaces), *output])
    return output


def sleep(seconds):
    for i in range(seconds):
        print(i, end=" ")
        time.sleep(1)
    print()


def encrypt(passwd: str, file_name: str):
    key = get_16bytes_str(passwd)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    with open(file_name, "r+b") as f:
        data = f.read()
        cipher_text, tag = cipher.encrypt_and_digest(data)
        f.seek(0)
        f.truncate()
        f.write(nonce)
        f.write(tag)
        f.write(cipher_text)
    print("Encryption done")


def decrypt(passwd: str, file_name: str):
    with open(file_name, "r+b") as f:
        key = get_16bytes_str(passwd)
        nonce = f.read(16)
        tag = f.read(16)
        cipher_text = f.read()
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        data = cipher.decrypt(cipher_text)
        try:
            cipher.verify(tag)
            f.seek(0)
            f.truncate()
            f.write(data)
            print("Decryption done")
        except ValueError:
            print("Key incorrect or message corrupted")


# -------------------------------- Main
if __name__ == "__main__":
    passwd = 'my_password'
    file_name = "file.txt"
    encrypt(passwd, file_name)
    sleep(3)
    decrypt(passwd, file_name)
