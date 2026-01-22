from pathlib import Path
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

MESSAGE_FILE = BASE_DIR / "message.txt"


def generate_key_and_iv():
    key = os.urandom(32)  # 32 bytes = 256-bit key
    iv = os.urandom(16)   # 16 bytes = AES block size for CBC IV

    OUTPUT_DIR.joinpath("aes_key.bin").write_bytes(key)
    OUTPUT_DIR.joinpath("aes_iv.bin").write_bytes(iv)


def encrypt_message():
    key = OUTPUT_DIR.joinpath("aes_key.bin").read_bytes()
    iv = OUTPUT_DIR.joinpath("aes_iv.bin").read_bytes()
    plaintext = MESSAGE_FILE.read_bytes()

    padder = padding.PKCS7(128).padder()  # AES block size is 128 bits
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()

    OUTPUT_DIR.joinpath("aes_encrypted.bin").write_bytes(ciphertext)


def decrypt_message():
    key = OUTPUT_DIR.joinpath("aes_key.bin").read_bytes()
    iv = OUTPUT_DIR.joinpath("aes_iv.bin").read_bytes()
    ciphertext = OUTPUT_DIR.joinpath("aes_encrypted.bin").read_bytes()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    OUTPUT_DIR.joinpath("aes_decrypted.txt").write_bytes(plaintext)


if __name__ == "__main__":
    generate_key_and_iv()
    encrypt_message()
    decrypt_message()
    print("Task 1 (AES): Encryption and decryption completed.")

