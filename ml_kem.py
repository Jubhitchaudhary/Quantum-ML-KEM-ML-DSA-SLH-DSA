import random

# BASIC PARAMETERS
DIM = 2    # Degree-1 polynomials (ax + b): 2 coefficients
MODULUS = 17  # Small prime modulus for easy tracking
NOISE_LEVEL = 1  # Noise from {-1, 0, 1}

# Polynomial Operations

def add_poly(p, q):
    return [(i + j) % MODULUS for i, j in zip(p, q)]

def sub_poly(p, q):
    return [(i - j) % MODULUS for i, j in zip(p, q)]

def mul_poly(p, q):
    p0, p1 = p
    q0, q1 = q
    return [
        (p0*q0 - p1*q1) % MODULUS,  # x^2 = -1 in this ring
        (p0*q1 + p1*q0) % MODULUS
    ]

# Random Polynomial Generators

def noise_poly():
    return [random.randint(-NOISE_LEVEL, NOISE_LEVEL) % MODULUS for _ in range(DIM)]

def uniform_poly():
    return [random.randint(0, MODULUS-1) for _ in range(DIM)]

# Keypair Generation (Alice)

def keygen():
    # Secrets
    sk0 = noise_poly()
    sk1 = noise_poly()
    secret = [sk0, sk1]

    # Public Matrix A
    A = [[uniform_poly(), uniform_poly()],
         [uniform_poly(), uniform_poly()]]

    # Error polynomials
    err0 = noise_poly()
    err1 = noise_poly()

    # b = A * s + e
    b0 = add_poly(mul_poly(A[0][0], sk0), mul_poly(A[0][1], sk1))
    b0 = add_poly(b0, err0)

    b1 = add_poly(mul_poly(A[1][0], sk0), mul_poly(A[1][1], sk1))
    b1 = add_poly(b1, err1)

    public = {'A': A, 'b': [b0, b1]}

    return public, secret

# Encryption (Bob)

def encapsulate(public_key):
    r0 = noise_poly()
    r1 = noise_poly()

    err_enc0 = noise_poly()
    err_enc1 = noise_poly()
    err_v = noise_poly()

    # u = A*r + e
    u0 = add_poly(mul_poly(public_key['A'][0][0], r0), mul_poly(public_key['A'][0][1], r1))
    u0 = add_poly(u0, err_enc0)

    u1 = add_poly(mul_poly(public_key['A'][1][0], r0), mul_poly(public_key['A'][1][1], r1))
    u1 = add_poly(u1, err_enc1)

    # v = b*r + e'
    v_temp = add_poly(mul_poly(public_key['b'][0], r0), mul_poly(public_key['b'][1], r1))
    v = add_poly(v_temp, err_v)

    # Derive shared secret
    shared_secret = [1 if val > MODULUS//2 else 0 for val in v]

    ciphertext = {'u': [u0, u1], 'v': v}

    return ciphertext, shared_secret

# Decryption (Alice)

def decapsulate(ciphertext, secret_key):
    s0, s1 = secret_key

    combined = add_poly(mul_poly(ciphertext['u'][0], s0), mul_poly(ciphertext['u'][1], s1))
    diff = sub_poly(ciphertext['v'], combined)

    recovered_secret = [1 if val > MODULUS//2 else 0 for val in diff]

    return recovered_secret

# EXECUTION

print("=== BASIC ML-KEM DEMO ===")
print(f"Polynomial Degree: 1 (DIM={DIM})")
print(f"Modulus: {MODULUS}, Noise Level: {NOISE_LEVEL}\n")

# Alice creates her keys
pub_key, sec_key = keygen()
print("Public Key (Alice):", pub_key)
print("Secret Key (Alice):", sec_key)

# Bob encrypts
cipher, bob_shared = encapsulate(pub_key)
print("\nCiphertext (Bob):", cipher)
print("Bob's Derived Shared Secret:", bob_shared)

# Alice decrypts
alice_shared = decapsulate(cipher, sec_key)
print("\nAlice's Recovered Shared Secret:", alice_shared)

# Check correctness
print("\nShared Secret Match?", bob_shared == alice_shared)
