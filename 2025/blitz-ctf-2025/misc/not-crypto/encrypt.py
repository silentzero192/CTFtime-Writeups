# uncompyle6 version 3.9.2
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: encrypt.py
# Compiled at: 2025-07-06 12:45:57
# Size of source mod 2**32: 6017 bytes
import os, sys, argparse, json, base64, logging, traceback
from getpass import getpass
from pathlib import Path
from typing import Tuple, Any, Dict, Callable
_SUPPORTED_BACKENDS = ('Crypto', 'cryptography')
_backend = None
for _b in _SUPPORTED_BACKENDS:
    try:
        if _b == "Crypto":
            from Crypto.Cipher import AES as _AES
            from Crypto.Protocol.KDF import PBKDF2 as _PBKDF2
            _backend = "Crypto"
        else:
            if _b == "cryptography":
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as _PBKDF2HMAC
                from cryptography.hazmat.primitives import hashes as _hashes
                from cryptography.hazmat.backends import default_backend as _default_backend
                _backend = "cryptography"
        if _backend:
            break
    except ImportError:
        continue

if not _backend:
    raise ImportError("No suitable crypto backend found. Install PyCryptodome or cryptography.")
_KDF_ITERATIONS = 200000
_SALT_SIZE = 16
_NONCE_SIZE = 12
_KEY_LENGTH = 32
logging.basicConfig(filename="encryptor.log",
  filemode="a",
  level=(logging.DEBUG),
  format="%(asctime)s - %(levelname)s - %(message)s")

class EncryptionError(Exception):
    pass


def derive_key(password: str, salt: bytes) -> bytes:
    if _backend == "Crypto":
        return _PBKDF2((password.encode("utf-8")), salt, dkLen=_KEY_LENGTH, count=_KDF_ITERATIONS,
          hmac_hash_module=None)
    else:
        kdf = _PBKDF2HMAC(algorithm=(_hashes.SHA256()),
          length=_KEY_LENGTH,
          salt=salt,
          iterations=_KDF_ITERATIONS,
          backend=(_default_backend()))
        return kdf.derive(password.encode("utf-8"))


def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> Tuple[(bytes, bytes, bytes)]:
    nonce = os.urandom(_NONCE_SIZE)
    if _backend == "Crypto":
        cipher = _AES.new(key, (_AES.MODE_GCM), nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    else:
        aesgcm = _AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        ciphertext, tag = ct[:-16], ct[-16:]
    return (
     nonce, ciphertext, tag)


def package_output(salt, nonce, ciphertext, tag):
    payload = {'salt':base64.b64encode(salt).decode("ascii"), 
     'nonce':base64.b64encode(nonce).decode("ascii"), 
     'ciphertext':base64.b64encode(ciphertext).decode("ascii"), 
     'tag':base64.b64encode(tag).decode("ascii")}
    return json.dumps(payload, indent=4)


def read_flag_file(path: Path) -> bytes:
    if not path.exists() or not path.is_file():
        raise EncryptionError(f"Flag file not found: {path}")
    return path.read_bytes()


def write_output_file(path: Path, data: str) -> None:
    path.write_text(data, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Encrypt a flag file with password-based AES-GCM.")
    parser.add_argument("flag_file", type=Path, help="Path to the plaintext flag file to encrypt")
    parser.add_argument("-o", "--output", type=Path, default=(Path("flag.enc.json")), help="Output JSON file (default: flag.enc.json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose console output")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.verbose:
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.DEBUG)
        logging.getLogger().addHandler(console)
    try:
        plaintext = read_flag_file(args.flag_file)
        password = getpass("Enter encryption password: ")
        if len(password) < 8:
            raise EncryptionError("Password must be at least 8 characters long.")
        salt = os.urandom(_SALT_SIZE)
        key = derive_key(password, salt)
        nonce, ciphertext, tag = encrypt_aes_gcm(key, plaintext)
        output_json = package_output(salt, nonce, ciphertext, tag)
        write_output_file(args.output, output_json)
        print(f"Flag encrypted successfully! Output written to: {args.output}")
    except Exception as exc:
        print(f"[!] Error: {exc}", file=(sys.stderr))
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Encrypt a flag file with password-based AES-GCM.")
    parser.add_argument("flag_file", type=Path, help="Path to the plaintext flag file to encrypt")
    parser.add_argument("-o", "--output", type=Path, default=(Path("flag.enc.json")), help="Output JSON file (default: flag.enc.json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose console output")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.verbose:
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.DEBUG)
        logging.getLogger().addHandler(console)
        logging.debug("Verbose mode enabled")
    try:
        plaintext = read_flag_file(args.flag_file)
        password = getpass("Enter encryption password: ")
        if len(password) < 8:
            raise EncryptionError("Password must be at least 8 characters long.")
        salt = os.urandom(_SALT_SIZE)
        key = derive_key(password, salt)
        nonce, ciphertext, tag = encrypt_aes_gcm(key, plaintext)
        output_json = package_output(salt, nonce, ciphertext, tag)
        write_output_file(args.output, output_json)
        print(f"Flag encrypted successfully! Output written to: {args.output}")
        logging.info("Encryption completed successfully")
    except Exception as exc:
        logging.error("An error occurred: %s", traceback.format_exc())
        print(f"[!] Error: {exc}", file=(sys.stderr))
        sys.exit(1)


if __name__ == "__main__":
    main()

# okay decompiling encrypt.cpython-36.pyc
