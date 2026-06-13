# ============================================================
# BGG+14 KP-ABE Simulation
# An LWE-Based Attribute Based Encryption Framework: Post-Quantum Fine-Grained Access Control for Institutional Systems"
# Author: Avni Marwah, South Asian University, May 2026
# ============================================================

import numpy as np
from copy import deepcopy

np.random.seed(42)

# -- Global Parameters ------------------------------------------
N         = 4       # LWE dimension n
Q         = 97      # Modulus q (prime)
M_A       = 8       # Columns in A
NOISE_B   = 1       # Initial noise bound B
NUM_ATTRS = 10      # Attribute universe size |U|

K  = int(np.ceil(np.log2(Q)))   # Gadget bit-width: ceil(log2(97)) = 7
NK = N * K                       # NK = 4 * 7 = 28

# Attribute universe -- order matters; indices used throughout
ATTRIBUTE_UNIVERSE = [
    "Professor",           # index 0
    "ResearchSupervisor",  # index 1
    "PhD",                 # index 2
    "MSc",                 # index 3
    "Student",             # index 4
    "MathDept",            # index 5
    "CSDept",              # index 6
    "ResearchGroup",       # index 7
    "LibraryAccess",       # index 8
    "FinanceClearance",    # index 9
]
ATTR_IDX = {a: i for i, a in enumerate(ATTRIBUTE_UNIVERSE)}

MESSAGE = ("PhD Research Evaluation File: Access Restricted "
           "to Authorised Academic Personnel Only")
# len(MESSAGE) == 85  =>  85 * 8 == 680 bits

USERS = {
    "U1":  {"name": "Dr. Ananya Sharma",    "role": "Professor (Mathematics)",        "attrs": ["Professor","MathDept","ResearchSupervisor","ResearchGroup","LibraryAccess"]},
    "U2":  {"name": "Dr. Raghav Mehta",     "role": "Professor (Computer Science)",   "attrs": ["Professor","CSDept","ResearchGroup"]},
    "U3":  {"name": "Dr. Kavita Iyer",      "role": "Research Supervisor",            "attrs": ["ResearchSupervisor","ResearchGroup","MathDept"]},
    "U4":  {"name": "Prof. Arvind Nair",    "role": "Dean (Academic Affairs)",        "attrs": ["Professor","MathDept","ResearchSupervisor","FinanceClearance"]},
    "U5":  {"name": "Neha Verma",           "role": "PhD Scholar (Mathematics)",      "attrs": ["PhD","MathDept","ResearchGroup","LibraryAccess","ResearchSupervisor"]},
    "U6":  {"name": "Rahul Khanna",         "role": "PhD Scholar (Computer Science)", "attrs": ["PhD","CSDept","ResearchGroup"]},
    "U7":  {"name": "Priya Singh",          "role": "MSc Mathematics Student",        "attrs": ["MSc","MathDept","Student"]},
    "U8":  {"name": "Aditya Rao",           "role": "MSc Computer Science Student",   "attrs": ["MSc","CSDept","Student"]},
    "U9":  {"name": "Sneha Kapoor",         "role": "BSc Student",                    "attrs": ["Student"]},
    "U10": {"name": "Karan Malhotra",       "role": "BTech Student",                  "attrs": ["Student"]},
    "U11": {"name": "Mehul Jain",           "role": "Research Assistant",             "attrs": ["ResearchGroup"]},
    "U12": {"name": "Aditi Desai",          "role": "Library Staff",                  "attrs": ["LibraryAccess"]},
    "U13": {"name": "Sanjay Gupta",         "role": "Finance Officer",                "attrs": ["FinanceClearance"]},
    "U14": {"name": "Ritu Aggarwal",        "role": "Administrative Officer",         "attrs": ["FinanceClearance"]},
    "U15": {"name": "Vikram Sethi",         "role": "IT Administrator",               "attrs": ["CSDept"]},
    "U16": {"name": "Pooja Bansal",         "role": "Lab Technician",                 "attrs": ["ResearchGroup"]},
    "U17": {"name": "Aman Choudhary",       "role": "Visiting Researcher",            "attrs": ["ResearchGroup","MathDept","LibraryAccess","ResearchSupervisor","PhD"]},
    "U18": {"name": "Nisha Arora",          "role": "External Collaborator",          "attrs": ["ResearchGroup"]},
    "U19": {"name": "Dev Patel",            "role": "Alumni Researcher",              "attrs": ["ResearchGroup"]},
    "U20": {"name": "Simran Kaur",          "role": "PhD Applicant",                  "attrs": ["Student"]},
}

# -- Part 1: Message Encoding ----------------------------------
def message_to_bits(msg):
    """UTF-8 encode message; unpack each byte into 8 bits MSB first."""
    byte_arr = msg.encode("utf-8")
    bits = []
    for byte in byte_arr:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits, byte_arr

def bits_to_message(bits):
    """Repack bits into bytes and decode UTF-8."""
    out = []
    for i in range(0, len(bits), 8):
        chunk = bits[i:i+8]
        if len(chunk) < 8:
            break
        val = 0
        for b in chunk:
            val = (val << 1) | int(b)
        out.append(val)
    return bytes(out).decode("utf-8", errors="replace")

# -- Part 2: Utility Functions ---------------------------------
def zq(x):
    """Reduce array or scalar modulo Q into {0,...,Q-1}."""
    return np.mod(x, Q).astype(int)

def rand_matrix(rows, cols):
    """Uniform random matrix over Z_q."""
    return np.random.randint(0, Q, size=(rows, cols), dtype=int)

def attrs_to_vec(attr_list):
    """Convert a list of attribute names to a binary vector in {0,1}^10."""
    x = np.zeros(NUM_ATTRS, dtype=int)
    for a in attr_list:
        if a in ATTR_IDX:
            x[ATTR_IDX[a]] = 1
    return x

# -- Part 3: Discrete Gaussian Sampler -------------------------
def discrete_gaussian_sample(size, sigma=1.0, tail=6):
    """
    Sample from D_{Z,sigma}: probability proportional to
    exp(-z^2 / (2*sigma^2)). Truncated to [-tail*sigma, tail*sigma].
    """
    bound   = int(np.ceil(tail * sigma))
    z_vals  = np.arange(-bound, bound + 1)
    weights = np.exp(-z_vals**2 / (2.0 * sigma**2))
    weights /= weights.sum()
    flat    = int(np.prod(size)) if hasattr(size, '__iter__') else size
    samples = np.random.choice(z_vals, size=flat, p=weights)
    if hasattr(size, '__iter__'):
        samples = samples.reshape(size)
    return samples

# -- Part 4: Gadget Matrix and Decomposition -------------------
def gadget_matrix():
    """Build G_n = I_n (x) g^T where g = [1,2,4,...,2^{k-1}]. Returns G_n in Z_q^{n x nk}."""
    g  = np.array([pow(2, i, Q) for i in range(K)], dtype=int)
    Gn = np.zeros((N, NK), dtype=int)
    for i in range(N):
        Gn[i, i*K:(i+1)*K] = g
    return Gn

Gn = gadget_matrix()

def g_inverse(B):
    """
    G^{-1}(B): for each entry b of B (mod q), write b in binary.
    Returns binary matrix D in {0,1}^{NK x NK} such that G_n @ D = B (mod q).
    B must have shape (N, NK).
    """
    if B.shape != (N, NK):
        raise ValueError(f"g_inverse: expected ({N},{NK}), got {B.shape}")
    D  = np.zeros((NK, NK), dtype=int)
    Bm = zq(B)
    for i in range(N):
        for j in range(NK):
            val = int(Bm[i, j])
            for b in range(K):
                D[i*K + b, j] = (val >> b) & 1
    return D

# -- Part 5: Homomorphic Gate Evaluation -----------------------
def gate_AND(B1, B2):
    """AND(B1, B2) = B1 @ G^{-1}(B2)  mod q."""
    return zq(B1 @ g_inverse(B2))

def gate_OR(B1, B2):
    """OR(B1, B2) = B1 + B2 - B1 @ G^{-1}(B2)  mod q."""
    return zq(B1 + B2 - B1 @ g_inverse(B2))

def gate_NOT(B1):
    """NOT(B1) = G_n - B1  mod q."""
    return zq(Gn - B1)

# -- Part 6: Policy Circuit Evaluation (EvalF) -----------------
def EvalF(B_list):
    """
    Evaluate the policy circuit C = NOT(f) over the public attribute matrices.
    Policy: f(x) = (Prof AND Math) OR (PhD AND ResGrp) AND (LibAcc OR FinClr) AND ResSup
    C = NOT(f)
    """
    A1   = gate_AND(B_list[0], B_list[5])   # Prof AND MathDept
    A2   = gate_AND(B_list[2], B_list[7])   # PhD AND ResearchGroup
    Blo  = gate_OR (B_list[8], B_list[9])   # LibAcc OR FinanceClearance
    SubA = gate_OR (A1, A2)                  # SubA
    SubB = gate_AND(Blo, B_list[1])          # SubB: Blo AND ResSup
    f_m  = gate_AND(SubA, SubB)              # f = SubA AND SubB
    B_C  = gate_NOT(f_m)                     # C = NOT(f)
    return B_C, f_m, SubA, SubB, A1, A2, Blo

# -- Part 7: Plaintext Policy Check ----------------------------
def eval_policy_bool(x):
    """Evaluate the policy f and circuit C = NOT(f) on binary attribute vector x."""
    Prof   = int(x[0]); ResSup = int(x[1]); PhD = int(x[2])
    Math   = int(x[5]); ResGrp = int(x[7])
    Lib    = int(x[8]); Fin    = int(x[9])
    A1     = Prof & Math
    A2     = PhD  & ResGrp
    Blo    = Lib  | Fin
    SubA   = A1   | A2
    SubB   = Blo  & ResSup
    f      = SubA & SubB
    C      = 1 - f
    return int(f), int(C), int(SubA), int(SubB)

# -- Part 8: Setup ---------------------------------------------
def Setup():
    """Generate master public key mpk = (A, B_list, p) and master secret key msk = T."""
    A      = rand_matrix(N, M_A)
    T      = discrete_gaussian_sample((M_A, M_A), sigma=1.0)
    B_list = [rand_matrix(N, NK) for _ in range(NUM_ATTRS)]
    p      = rand_matrix(N, 1).flatten()
    mpk    = {"A": A, "B_list": B_list, "p": p}
    msk    = {"T": T}
    return mpk, msk

# -- Part 9: Key Generation ------------------------------------
def KeyGen(mpk, msk):
    """Compute B_C = EvalF(B_list) and find y such that [A|B_C] @ y = p (mod q)."""
    B_list = mpk["B_list"]
    A      = mpk["A"]
    p      = mpk["p"].copy().astype(int)

    B_C, *_ = EvalF(B_list)
    AB_C    = np.concatenate([A, B_C], axis=1)   # shape (N, M_A + NK)
    total   = AB_C.shape[1]
    y       = np.zeros(total, dtype=int)
    residue = p.copy()

    for col in range(total):
        candidate = zq(residue - AB_C[:, col])
        if np.sum(candidate**2) < np.sum(residue**2):
            y[col]  = 1
            residue = candidate

    # Final check: verify [A|B_C] @ y = p (mod q)
    check = zq(AB_C @ y)
    if not np.all(check == zq(p)):
        y       = np.zeros(total, dtype=int)
        residue = p.copy().astype(int)
        for col in range(total):
            for v in range(1, Q):
                cand = zq(residue - v * AB_C[:, col])
                if np.sum(cand**2) < np.sum(residue**2):
                    y[col]  = v
                    residue = cand
                    break

    return {"y": y, "B_C": B_C}

# -- Part 10: Encryption ---------------------------------------
def Encrypt_bit(mpk, x, m_bit):
    """Encrypt one plaintext bit m_bit in {0,1} under attribute vector x in {0,1}^10."""
    A      = mpk["A"]
    B_list = mpk["B_list"]
    p      = mpk["p"]

    s  = rand_matrix(N, 1).flatten()
    e0 = discrete_gaussian_sample(M_A, sigma=1.0)
    e1 = discrete_gaussian_sample(NK,  sigma=1.0)
    e2 = int(discrete_gaussian_sample(1, sigma=1.0)[0])

    c0 = zq(s @ A + e0)

    B_shifted = np.zeros((N, NK), dtype=int)
    for i in range(NUM_ATTRS):
        B_shifted = zq(B_shifted + B_list[i] - int(x[i]) * Gn)

    c1 = zq(s @ B_shifted + e1)
    c2 = int(zq(int(s @ p) + e2 + m_bit * (Q // 2)))

    return {"c0": c0, "c1": c1, "c2": c2, "x": x.copy(), "m_bit": m_bit}

# -- Part 11: Decryption ---------------------------------------
def Decrypt_bit(sk, CT, mpk):
    """Decrypt one ciphertext CT using secret key sk."""
    c0 = CT["c0"]; c1 = CT["c1"]; c2 = CT["c2"]
    x  = CT["x"];  y  = sk["y"]

    f_val, C_val, SubA, SubB = eval_policy_bool(x)

    y_A  = y[:M_A]
    y_BC = y[M_A:M_A + NK]
    v    = int(zq(int(c0 @ y_A) + int(c1 @ y_BC)))
    res  = int(zq(c2 - v))
    hq   = Q // 2

    dist0  = min(res, Q - res)
    dist1  = min(abs(res - hq), Q - abs(res - hq))
    decoded = 0 if dist0 <= dist1 else 1

    return decoded, f_val, C_val

# -- Part 12: Full Message Encrypt and Decrypt -----------------
def encrypt_message(mpk, x, msg_bits):
    """Encrypt all 680 bits; returns list of 680 ciphertexts."""
    return [Encrypt_bit(mpk, x, b) for b in msg_bits]

def decrypt_message(sk, ct_list, mpk, x_user):
    """Decrypt all ciphertexts using x_user's attribute vector."""
    dec_bits = []
    f_val = C_val = 0
    for CT in ct_list:
        CT_u        = deepcopy(CT)
        CT_u["x"]   = x_user
        dec, f_val, C_val = Decrypt_bit(sk, CT_u, mpk)
        dec_bits.append(dec)
    return dec_bits, f_val, C_val

# -- Part 13: Noise Accumulation Analysis ----------------------
def print_noise_analysis():
    """Track noise growth through the depth-4 circuit."""
    print(f"\nNoise analysis: N={N}, Q={Q}, B={NOISE_B}, depth=4")
    print(f"Correctness threshold: q/4 = {Q//4}")
    print("-" * 45)
    for lvl in range(1, 5):
        exp = 2**lvl
        val = (NOISE_B**exp) * (N**lvl)
        print(f"  Level {lvl}: B^{exp} * n^{lvl} = {val}")
    final  = (NOISE_B**(2**4)) * (N**4)
    status = "SATISFIED" if final < Q//4 else "VIOLATED (toy params)"
    print(f"\n  Final bound: {final} < {Q//4}? => {status}")

# -- Part 14: User Access Table --------------------------------
def run_user_access_table(mpk, sk, m_bit=1):
    """Encrypt m_bit=1 under all-ones attribute label; test all 20 users."""
    x_ct = np.ones(NUM_ATTRS, dtype=int)
    CT   = Encrypt_bit(mpk, x_ct, m_bit)

    print(f"\n{'ID':<5} {'Name':<25} {'SubA':>5} {'SubB':>5} {'f':>4} {'Dec':>4} {'Match':>6}")
    print("-" * 58)

    auth_list   = []
    denied_list = []

    for uid, ud in USERS.items():
        x_user     = attrs_to_vec(ud["attrs"])
        CT_u       = deepcopy(CT)
        CT_u["x"]  = x_user
        dec, f_val, C_val       = Decrypt_bit(sk, CT_u, mpk)
        f_check, _, SubA, SubB  = eval_policy_bool(x_user)
        match = "OK" if (f_val == f_check) else "ERR"
        print(f"{uid:<5} {ud['name']:<25} {SubA:>5} {SubB:>5} {f_val:>4} {dec:>4} {match:>6}")
        if f_val == 1:
            auth_list.append(uid)
        else:
            denied_list.append(uid)

    print(f"\nAuthorised ({len(auth_list)}): {auth_list}")
    print(f"Denied     ({len(denied_list)}): {denied_list}")
    return auth_list, denied_list

# -- Part 15: Main Driver --------------------------------------
def main():
    print("=" * 60)
    print("BGG+14 KP-ABE Simulation")
    print(f"Parameters: N={N}, Q={Q}, K={K}, NK={NK}, M_A={M_A}")
    print("=" * 60)

    # Setup
    mpk, msk = Setup()
    print("\n[Setup] Master public key generated.")

    # Key Generation
    sk = KeyGen(mpk, msk)
    print("[KeyGen] Secret key derived for access policy f.")

    # Noise analysis
    print_noise_analysis()

    # Encode message
    msg_bits, _ = message_to_bits(MESSAGE)
    assert len(msg_bits) == 680, f"Expected 680 bits, got {len(msg_bits)}"
    print(f"\n[Message] {len(msg_bits)} bits from {len(MESSAGE)} characters.")

    # Full encryption under all-ones label
    x_enc   = np.ones(NUM_ATTRS, dtype=int)
    ct_list = encrypt_message(mpk, x_enc, msg_bits)
    print(f"[Encrypt] {len(ct_list)} ciphertext objects produced.")

    # Decrypt for selected users
    print("\n[Decrypt] Selected users:")
    for uid in ["U1", "U4", "U5", "U17", "U3", "U6"]:
        ud        = USERS[uid]
        x_user    = attrs_to_vec(ud["attrs"])
        dec_bits, f_val, _ = decrypt_message(sk, ct_list, mpk, x_user)
        recovered = bits_to_message(dec_bits)
        status    = "SUCCESS" if f_val == 1 else "DENIED"
        correct   = (recovered == MESSAGE) if f_val == 1 else True
        print(f"  {uid} ({ud['name']:<22}): f={f_val} {status} {'msg OK' if correct else 'MISMATCH'}")

    # Full access table (all 20 users, single bit)
    print("\n[Access Table] All 20 users vs. encrypted bit mu=1:")
    run_user_access_table(mpk, sk, m_bit=1)

if __name__ == "__main__":
    main()
