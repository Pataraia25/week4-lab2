from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

MESSAGE_FILE = BASE_DIR / "message.txt"


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    OUTPUT_DIR.joinpath("rsa_private.pem").write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

    OUTPUT_DIR.joinpath("rsa_public.pem").write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )


def encrypt_message():
    public_key = serialization.load_pem_public_key(
        OUTPUT_DIR.joinpath("rsa_public.pem").read_bytes()
    )

    plaintext = MESSAGE_FILE.read_bytes()

    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    OUTPUT_DIR.joinpath("rsa_encrypted.bin").write_bytes(ciphertext)


def decrypt_message():
    private_key = serialization.load_pem_private_key(
        OUTPUT_DIR.joinpath("rsa_private.pem").read_bytes(),
        password=None
    )

    ciphertext = OUTPUT_DIR.joinpath("rsa_encrypted.bin").read_bytes()

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    OUTPUT_DIR.joinpath("rsa_decrypted.txt").write_bytes(plaintext)


if __name__ == "__main__":
    generate_rsa_keys()
    encrypt_message()
    decrypt_message()
    print("Task 1 (RSA): Encryption and decryption completed.")

