import os
import hashlib

def pseudo_keygen():
    # Generate a secret key and derive a public key
    sk = os.urandom(32)  # secret key (random bytes)
    pk = hashlib.sha256(sk).digest()  # public key (hashed secret)
    return pk, sk

def pseudo_encapsulate(pk):
    # Random message acts as the "ephemeral" key material
    msg = os.urandom(32)
    # Ciphertext is hash of msg and public key
    ct = hashlib.sha256(msg + pk).digest()
    # Shared secret is derived from the ciphertext
    ss = hashlib.sha256(ct).digest()
    return ct, ss

def pseudo_decapsulate(ct, sk):
    # We assume ct is valid; in real systems we'd verify it
    # Shared secret is derived same way as in encapsulate
    ss = hashlib.sha256(ct).digest()
    return ss

if __name__ == "__main__":
    print("🔑 Generating Keypair...")
    pk, sk = pseudo_keygen()

    print("🔐 Encapsulating...")
    ct, ss1 = pseudo_encapsulate(pk)
    print("Ciphertext:", ct.hex())

    print("🔓 Decapsulating...")
    ss2 = pseudo_decapsulate(ct, sk)

    print("Shared Secret (Original):", ss1.hex())
    print("Shared Secret (Recovered):", ss2.hex())

    if ss1 == ss2:
        print("✅ Shared secrets match! ML-KEM simulation successful.")
    else:
        print("❌ Shared secrets do not match.")

