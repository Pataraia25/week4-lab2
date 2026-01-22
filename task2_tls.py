import ssl
import socket
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

REPORT_FILE = BASE_DIR / "tls_report.txt"
CERT_FILE = OUTPUT_DIR / "server_cert.pem"


def inspect_tls(host: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()

    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            tls_version = ssock.version()
            cipher = ssock.cipher()  # (cipher_name, protocol, secret_bits)
            cert = ssock.getpeercert()
            der_cert = ssock.getpeercert(binary_form=True)

    pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
    CERT_FILE.write_text(pem_cert, encoding="utf-8")

    return {
        "host": host,
        "port": port,
        "tls_version": tls_version,
        "cipher": cipher,
        "issuer": cert.get("issuer"),
        "subject": cert.get("subject"),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "cert_path": str(CERT_FILE),
    }


def write_report(info: dict) -> None:
    cipher_name, cipher_proto, bits = info["cipher"]

    text = (
        "TLS Inspection Report (Python)\n\n"
        f"Target: {info['host']}:{info['port']}\n"
        f"Negotiated TLS Version: {info['tls_version']}\n"
        f"Cipher Suite: {cipher_name} ({cipher_proto}, {bits} bits)\n"
        f"Certificate Subject: {info['subject']}\n"
        f"Certificate Issuer: {info['issuer']}\n"
        f"Certificate Validity: {info['not_before']}  ->  {info['not_after']}\n"
        f"Saved Server Certificate (PEM): {info['cert_path']}\n\n"
        "How TLS helps prevent MITM attacks:\n"
        "- The server proves identity using an X.509 certificate signed by a trusted CA (or chain).\n"
        "- The client validates the trust chain and verifies the certificate matches the hostname.\n"
        "- The handshake negotiates session keys so traffic is encrypted and tamper-evident.\n"
        "- Without a trusted certificate for the same hostname, an attacker cannot impersonate the server.\n\n"
        "How HTTPS protects data in transit:\n"
        "- Confidentiality via encryption (session keys).\n"
        "- Integrity via authenticated encryption/MAC (prevents silent modification).\n"
        "- Authentication via certificate validation (prevents spoofed endpoints).\n"
    )

    REPORT_FILE.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    host = input("Enter HTTPS host (e.g., example.com): ").strip()
    if not host:
        print("No host provided. Exiting.")
        raise SystemExit(1)

    info = inspect_tls(host)
    write_report(info)

    print("Task 2 (TLS): Inspection completed.")
    print("Wrote:", REPORT_FILE)
    print("Saved certificate:", CERT_FILE)

