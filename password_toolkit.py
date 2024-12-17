import hashlib
import bcrypt
import re
import argparse
import os
from passlib.context import CryptContext
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from base64 import urlsafe_b64encode, urlsafe_b64decode
import subprocess

# Initialize password hashing context for strong policies
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Function to enforce password policy
def enforce_password_policy(password):
    if len(password) < 8:
        print("[WARNING] Password must be at least 8 characters long.")
        return False
    if not re.search(r"[A-Za-z]", password):
        print("[WARNING] Password must contain at least one letter.")
        return False
    if not re.search(r"\d", password):
        print("[WARNING] Password must contain at least one number.")
        return False
    if not re.search(r"[@#$%^&*()_+=\-!]", password):
        print("[WARNING] Password must contain at least one special character (@, #, $, etc.).")
        return False
    print("[SUCCESS] Password meets the policy requirements.")
    return True

# Function to hash the password using SHA-256
def hash_sha256(password):
    print("[INFO] Hashing password using SHA-256...")
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    print(f"[RESULT] SHA-256 Hash: {sha256_hash}")
    return sha256_hash

# Function to hash the password using bcrypt
def hash_bcrypt(password):
    print("[INFO] Hashing password using bcrypt...")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    print(f"[RESULT] bcrypt Hash: {hashed.decode()}")
    return hashed.decode()

# Function to generate RSA keys and encrypt the password
def rsa_encrypt_decrypt(password):
    print("[INFO] Generating RSA key pair...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Serialize and save the keys (optional step)
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("[INFO] Encrypting the password using RSA...")
    encrypted = public_key.encrypt(
        password.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    print(f"[RESULT] Encrypted Password: {urlsafe_b64encode(encrypted).decode()}")

    print("[INFO] Decrypting the password using RSA...")
    decrypted = private_key.decrypt(
        urlsafe_b64decode(urlsafe_b64encode(encrypted)),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    print(f"[RESULT] Decrypted Password: {decrypted.decode()}")

# Function to run Hashcat for cracking a password hash
def run_hashcat(hash_file, wordlist):
    print("[INFO] Running Hashcat for brute-force attack...")
    command = f"hashcat -a 0 -m 100 {hash_file} {wordlist} --force"
    print(f"[COMMAND] {command}")
    os.system(command)

# Function to run John the Ripper for cracking a password hash
def run_john(hash_file):
    print("[INFO] Running John the Ripper to crack hashes...")
    command = f"john {hash_file}"
    print(f"[COMMAND] {command}")
    os.system(command)

# Main function to parse arguments and execute the toolkit
def main():
    parser = argparse.ArgumentParser(description="Password Cracking and Protection Toolkit")
    parser.add_argument("--password", type=str, help="Test the password for policy, hashing, and encryption.")
    parser.add_argument("--hashcat", nargs=2, metavar=('hash_file', 'wordlist'), help="Run Hashcat with a hash file and wordlist.")
    parser.add_argument("--john", type=str, metavar="hash_file", help="Run John the Ripper with a hash file.")
    args = parser.parse_args()

    if args.password:
        print("\n[INFO] Enforcing password policy...")
        if enforce_password_policy(args.password):
            sha_hash = hash_sha256(args.password)
            bcrypt_hash = hash_bcrypt(args.password)
            rsa_encrypt_decrypt(args.password)

    if args.hashcat:
        hash_file, wordlist = args.hashcat
        run_hashcat(hash_file, wordlist)

    if args.john:
        run_john(args.john)

if __name__ == "__main__":
    main()
