from TAEG import threshold_eigamal as taeg
from TAEG.utils import randmpz_in
from gmpy2 import powmod
import random
import time

PLAINTEXT_SPACE = 2 ** 12


class PrivateKey():
    def __init__(self, x):
        self.x = x


class CS():
    def __init__(self, sk=None):
        self.sk = PrivateKey

    def gen_keypair(self, p, q, g):
        x = randmpz_in(q)
        h = powmod(g, x, p)
        self.sk = PrivateKey(x)
        # sk, h = taeg.generate_sever_key_pair(p, q, g)
        return h


def secure_mul_protocol(encm1, encm2, CS1, CS2, pk, gm_dict):
    # For the CS1,
    # starTim = time.perf_counter()
    u = randmpz_in(PLAINTEXT_SPACE)
    ciphertext1 = encm1.sca_add(u, pk)  # E(m1+u)
    M1 = taeg.partial_decrypt(ciphertext1, pk, CS1.sk) # M_{m1+u}

    # For the CS2,
    gm_16 = taeg.partial_decrypt(M1, pk, CS2.sk)
    rec_plaintext1 = taeg.dlog(gm_16.c2, gm_dict)  # m1+u
    ciphertext2 = encm2.sca_mul(rec_plaintext1, pk)  # E(m2 * (m1+u))

    # For the CS1,
    ciphertext3 = encm2.sca_mul(u, pk)  # E(m2*u)
    ciphertext3_inv = ciphertext3.c_inv(pk)  # E(-m2*u)
    enc_m1_times_m2 = ciphertext2.c_add(ciphertext3_inv, pk)  # E(m2 * (m1+u))-E(-m2*u)= E(m1*m2)
    # sum_time = time.perf_counter() - starTim

    return enc_m1_times_m2


def secure_comp_protocol(encm1, encm2, CS1, CS2, pk, gm_dict):
    # For the CS1,
    b = random.randint(0, 1)
    if b == 0:
        cihpertext1 = encm2.c_inv(pk)
        encd = encm1.c_add(cihpertext1, pk)
    else:
        ciphertext1 = encm1.c_inv(pk)
        encd = encm2.c_add(ciphertext1, pk)

    u = random.randint(1, 2 ** 4)
    ciphertext2 = encd.sca_mul(u, pk)
    e = random.randint(1 - u, u - 1)
    ciphertext3 = ciphertext2.sca_add(e, pk)
    M1 = taeg.partial_decrypt(ciphertext3, pk, CS1.sk)

    # For the CS2,
    gm_16 = taeg.partial_decrypt(M1, pk, CS2.sk)
    rec_plaintext1 = taeg.dlog(gm_16.c2, gm_dict)  # d*u+e
    enc0 = taeg.encrypt(0, pk)
    enc1 = taeg.encrypt(1, pk)

    if rec_plaintext1 > 0:
        compare_result = [enc0, enc1]
    else:
        compare_result = [enc1, enc0]

    # For the CS1,
    if b == 1:
        rotated_cr = [compare_result[1], compare_result[0]]
    else:
        rotated_cr = compare_result

    return rotated_cr


def secure_sba_protocol(encm, CS1, CS2, pk, gm_dict):
    enc0 = taeg.encrypt(0, pk)
    compare_result = secure_comp_protocol(encm, enc0, CS1, CS2, pk, gm_dict)
    encm_inv = encm.c_inv(pk)
    ciphertext_list = [encm_inv, encm]
    ct0 = secure_mul_protocol(compare_result[0], ciphertext_list[0], CS1, CS2, pk, gm_dict)
    ct1 = secure_mul_protocol(compare_result[1], ciphertext_list[1], CS1, CS2, pk, gm_dict)
    ciphertext1 = ct0.c_add(ct1, pk)
    return compare_result[0], ciphertext1
