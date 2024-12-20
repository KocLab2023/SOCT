import gmpy2
from TAEG.utils import relat_prime_in_set, randmpz_in, r_divides_p_1_proce, \
    mulmod, r_divides_p_1
from gmpy2 import invert, powmod, mpz, mod, divexact
import random

DEFAULT_P_LENGTH = 2048
DEFAULT_Q_LENGTH = 256
LIST_LEN = 17


class PublicKey():
    def __init__(self, p, q, g, h1, h2):
        self.p = p
        self.q = q
        self.g = g
        self.h1 = h1
        self.h2 = h2
        self.h = None

    def pre_compute_h(self, h1, h2, p):
        self.h = h1 * h2 % p


class PrivateKey():
    def __init__(self, x):
        self.x = x


class Ciphertext():
    def __init__(self, c1, c2):
        self.c1 = c1
        self.c2 = c2
        # self.p = p

    def c_add(self, other, Pubkey):
        tc1 = self.c1 * other.c1 % Pubkey.p
        tc2 = self.c2 * other.c2 % Pubkey.p
        return Ciphertext(tc1, tc2)

    def sca_add(self, scalar, Pubkey):
        es = encrypt(scalar, Pubkey)
        tc1 = self.c1 * es.c1 % Pubkey.p
        tc2 = self.c2 * es.c2 % Pubkey.p
        return Ciphertext(tc1, tc2)

    def sca_mul(self, scalar, Pubkey):
        tsc1 = powmod(self.c1, scalar, Pubkey.p)
        tsc2 = powmod(self.c2, scalar, Pubkey.p)
        es = encrypt(0, Pubkey)
        tc1 = es.c1 * tsc1 % Pubkey.p
        tc2 = es.c2 * tsc2 % Pubkey.p
        return Ciphertext(tc1, tc2)

    def c_inv(self, Pubkey):
        tc1 = invert(self.c1, Pubkey.p)
        tc2 = invert(self.c2, Pubkey.p)
        return Ciphertext(tc1, tc2)

    def c_inv1(self, Pubkey):
        tc1 = powmod(self.c1, -1, Pubkey.p)
        tc2 = powmod(self.c2, -1, Pubkey.p)
        return Ciphertext(tc1, tc2)


class EigamalError(Exception):
    pass


def generate_group(p_len=DEFAULT_P_LENGTH, q_len=DEFAULT_Q_LENGTH,
                   proce_flag=True):
    """
    EIGamal key generation, satisfied:
    (q|p-1), g is a generator of cyclic subgroup ord(g)=q
    h=g^x (mod p) where x is privatekey

    :param p_len: DEFAULT_P_LENGTH=2048
    :param q_len: DEFAULT_Q_LENGTH=256
    :return: publickey(class.p, q, g, h), privatekey(class.x)
    """
    if proce_flag == True:
        q, p = r_divides_p_1_proce(q_len, p_len)
    else:
        q, p = r_divides_p_1(q_len, p_len)

    y = relat_prime_in_set(p)

    d = divexact(p - 1, q)
    g = powmod(y, d, p)
    return p, q, g


def generate_sever_key_pair(p, q, g):
    """
    EIGamal key generation, satisfied:
    (q|p-1), g is a generator of cyclic subgroup ord(g)=q
    h=g^x (mod p) where x is privatekey

    :param p_len: DEFAULT_P_LENGTH=2048
    :param q_len: DEFAULT_Q_LENGTH=256
    :return: publickey(class.p, q, g, h), privatekey(class.x)
    """
    x = randmpz_in(q)
    h = powmod(g, x, p)

    Prikey = PrivateKey(x)

    return Prikey, h


def gen_gm_mapping(g, p):
    # ----------generate map list (gm, m)----------------
    gm_poslist = []
    gm_invlist = []
    m_space = pow(2, LIST_LEN)
    for i in range(m_space):
        m_mpz = mpz(i)
        gm = powmod(g, m_mpz, p)
        gm_inv = invert(gm, p)
        gm_invlist.append(gm_inv)
        gm_poslist.append(gm)
    gm_maplist = []
    gm_maplist.append(gm_poslist)
    gm_maplist.append(gm_invlist)

    gm_pos_strlist = []
    gm_inv_strlist = []
    for i in range(len(gm_poslist)):
        gm_pos_strlist.append(str(gm_poslist[i]))
        gm_inv_strlist.append(str(gm_invlist[i]))

    pos_dict = {val: idx for idx, val in enumerate(gm_pos_strlist)}
    inv_dict = {val: idx for idx, val in enumerate(gm_inv_strlist)}
    for i in inv_dict:
        inv_dict[i] = -inv_dict[i]

    merged_dict = pos_dict.copy()
    merged_dict.update(inv_dict)

    return merged_dict


def encrypt(m, Pubkey):
    """
    encrypt m by g^m and publickey, r is random number in set of mod q

    c1 = g^r (mod p), c2 = g^m * h^r (mod p)

    :param encode_gm:(mpz)
    :param Pubkey:(class)
    :return: (class.c1,c2)(mpz)
    """
    r = randmpz_in(Pubkey.q)
    # r = gmpy2.mpz(r)
    c1 = powmod(Pubkey.g, r, Pubkey.p)
    c2 = powmod(Pubkey.g, mpz(m), Pubkey.p) * powmod(Pubkey.h, r, Pubkey.p) % Pubkey.p
    # gm = powmod(Pubkey.g, mpz(m), Pubkey.p)
    # h1r = powmod(Pubkey.h1, r, Pubkey.p)
    # h2r = powmod(Pubkey.h2, r, Pubkey.p)
    # c2 = (gm * h1r * h2r) % Pubkey.p

    ciphertext = Ciphertext(c1, c2)
    return ciphertext


def partial_decrypt(ciphertext, Pubkey, Prikey):
    c1 = ciphertext.c1
    u1 = powmod(c1, Prikey.x, Pubkey.p)
    u1_inv = invert(u1, Pubkey.p)
    u2 = mod(u1_inv * ciphertext.c2, Pubkey.p)

    ciphertext = Ciphertext(c1, u2)
    return ciphertext


def dlog(gm, gm_dict):
    m = gm_dict[str(gm)]
    return m


def decrypt(ciphertext, Pubkey, Prikey1, Prikey2, gm_dict):
    """
    decrypt (c1,c2) by privatekey, encode_map, publickey

    g^m = c2 * inverse(c1^x) (mod p)

    by search g^m in encode map list to find m

    :param c_pair:(class)
    :param Pubkey:(class)
    :param Prikey:(class)
    :param encode_map:(list.class)
    :return: res_m (mpz) decrypt result
    """
    M1 = partial_decrypt(ciphertext, Pubkey, Prikey1)
    m1 = partial_decrypt(M1, Pubkey, Prikey2)

    res_m = dlog(m1.c2, gm_dict)

    return res_m


def user_decrypt(ciphertext, Pubkey, user_lambda, gm_dict):
    c1 = ciphertext.c1
    u1 = powmod(c1, user_lambda, Pubkey.p)
    u1_inv = invert(u1, Pubkey.p)
    u2 = mod(u1_inv * ciphertext.c2, Pubkey.p)
    res_m = dlog(u2, gm_dict)

    return res_m
# def eigamal_homomorphic_additive(C_text1, C_text2, Pub_k):
#     """
#     multiple in ciphertext, without decrypt (equals add in plaintext)
#
#     :param C_text1: ciphertext1 (class)
#     :param C_text2: ciphertext2 (class)
#     :param Pub_k: public key (class)
#     :return: E(m1)*E(m2) (mod n), ciphertext(class)
#     """
#     return C_text1.c_mulmod(C_text2, Pub_k.p)
#
#
# def eigamal_homomorphic_multiplicative_constant(C_text, scalar_k, Pub_k):
#     """
#     ciphertext power of scalar number, without decrypt (equals multiple in plaintext)
#
#     :param C_text: ciphertext (class)
#     :param scalar_k: scalar integer k
#     :param Pub_k: public key (class)
#     :return: E(m)^k (mod n), ciphertext(class)
#     """
#     return C_text.sca_powmod(scalar_k, Pub_k.p)
#
#
# def eigamal_homomorphic_additive_constant(C_text, scalar_k, Pub_k):
#     """
#     E(m)=(c1,c2), c2*g^k (mod n), without decrypt (equals add in
#     plaintext)
#
#     :param C_text: ciphertext (class)
#     :param scalar_k: scalar integer k
#     :param Pub_k: public key (class)
#     :return: (c1 , c2*g^k) (mod n), ciphertext(class)
#     """
#     sca_mul = C_text
#     gk = powmod(Pub_k.g, scalar_k, Pub_k.p)
#     sca_mul.c2 = mulmod(C_text.c2, gk, Pub_k.p)
#     return sca_mul
