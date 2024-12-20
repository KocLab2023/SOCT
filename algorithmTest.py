from TAEG import threshold_eigamal as taeg
from TAEG.utils import randmpz_in
from gmpy2 import mpz, powmod, invert
from protocols import secure_computation_protocols as sp
import time


def setup_group():
    '''
    Read the group parameters from files
    :return:
    '''
    file = open("group parameters\g2048.txt", 'r')  # Open file EIGamal_group_g.txt containing generator g
    g = file.read()  # Read the data from file and assign it to variable g
    file.close()  # Close the file
    file = open("group parameters\p2048.txt", 'r')  # Open file EIGamal_group_p.txt containing prime modulus p
    p = file.read()  # Read the data from file and assign it to variable p
    file.close()  # Close the file
    file = open("group parameters\q2048.txt", 'r')  # Open file EIGamal_group_q.txt containing prime order q
    q = file.read()  # Read the data from file and assign it to variable q
    file.close()  # Close the file
    g = mpz(g)  # Convert g to a gmpy2 object
    p = mpz(p)  # Convert p to a gmpy2 object
    q = mpz(q)  # Convert q to a gmpy2 object
    return p, q, g


def dlog(gm, gm_dict):
    m = gm_dict[str(gm)]
    return m


def enc_timetest(m):
    st = time.perf_counter()
    encm1 = taeg.encrypt(m, pk)
    et = time.perf_counter()
    return et - st


def user_dec_timetest(m):
    encm1 = taeg.encrypt(m, pk)
    user_lambda = CS1.sk.x + CS2.sk.x % pk.q
    st = time.perf_counter()
    res = taeg.user_decrypt(encm1, pk, user_lambda, gm_dict)
    et = time.perf_counter()

    # Verify correctness
    assert m == res
    return et - st


def dec_timetest(m):
    encm1 = taeg.encrypt(m, pk)
    st = time.perf_counter()
    res = taeg.decrypt(encm1, pk, CS1.sk, CS2.sk, gm_dict)
    et = time.perf_counter()

    # Verify correctness
    assert m == res
    return et - st


def pdec1_timetest(m):
    encm1 = taeg.encrypt(m, pk)
    st = time.perf_counter()
    res = taeg.partial_decrypt(encm1, pk, CS1.sk)
    et = time.perf_counter()
    return et - st


def pdec2_timetest(m):
    encm1 = taeg.encrypt(m, pk)
    res1 = taeg.partial_decrypt(encm1, pk, CS1.sk)
    st = time.perf_counter()
    res = taeg.partial_decrypt(res1, pk, CS2.sk)
    res_m = dlog(res.c2, gm_dict)
    et = time.perf_counter()

    # Verify correctness
    assert m == res_m
    return et - st


def ciphertext_add_timetest(m):
    encm1 = taeg.encrypt(m, pk)
    encm2 = taeg.encrypt(m, pk)

    st = time.perf_counter()
    res = encm1.c_add(encm2, pk)
    et = time.perf_counter()

    # Verify correctness
    res_m = taeg.decrypt(res, pk, CS1.sk, CS2.sk, gm_dict)
    assert res_m == m + m
    return et - st


def scalar_mul_timetest(m):
    encm1 = taeg.encrypt(m, pk)
    e0 = taeg.encrypt(0, pk)
    s = randmpz_in(2 ** 3)

    st = time.perf_counter()
    tsc1 = powmod(encm1.c1, s, pk.p)
    tsc2 = powmod(encm1.c2, s, pk.p)
    tc1 = e0.c1 * tsc1 % pk.p
    tc2 = e0.c2 * tsc2 % pk.p
    res = taeg.Ciphertext(tc1, tc2)
    et = time.perf_counter()

    # Verify correctness
    res_m = taeg.decrypt(res, pk, CS1.sk, CS2.sk, gm_dict)
    assert res_m == m * s
    return et - st


def ciphertext_sub_timetest(m):
    encm1 = taeg.encrypt(m, pk)
    m2 = randmpz_in(2 ** 12)
    encm2 = taeg.encrypt(m2, pk)

    st = time.perf_counter()
    encm2_inv = encm2.c_inv1(pk)
    res = encm1.c_add(encm2_inv, pk)
    et = time.perf_counter()


    # Verify correctness
    res_m = taeg.decrypt(res, pk, CS1.sk, CS2.sk, gm_dict)
    assert res_m == m - m2
    return et - st


# ----------generate parameters----------
p, q, g = setup_group()
CS1 = sp.CS()
h1 = CS1.gen_keypair(p, q, g)

CS2 = sp.CS()
h2 = CS2.gen_keypair(p, q, g)

pk = taeg.PublicKey(p, q, g, h1, h2)
pk.pre_compute_h(h1, h2, p)
gm_dict = taeg.gen_gm_mapping(g, p)

print('The public key is ')
print('p = ', p, ' with the bit length ', p.bit_length())
print('q = ', q, ' with the bit length ', q.bit_length())
print('g = ', g, ' with the bit length ', g.bit_length())
print('h1 = ', h1, ' with the bit length ', h1.bit_length())
print('h2 = ', h2, ' with the bit length ', h2.bit_length())
print('--------------------------------')
# ------------- test encryption function time -----
sum = 0
m = randmpz_in(2 ** 12)
for i in range(1000):
    sum += enc_timetest(m)

tt = (sum / 100) * 1000
print('The encryption function cost: ', "{:.6f}".format(sum), ' ms')

# ------------- test user decryption function time -----
sum = 0
m = randmpz_in(2 ** 12)
for i in range(100):
    sum += user_dec_timetest(m)

tt = (sum / 100) * 1000
print('The user decryption function cost: ', "{:.3f}".format(tt), ' ms')

# ------------- test severs decryption function time -----
sum = 0
m = randmpz_in(2 ** 12)
for i in range(100):
    sum += dec_timetest(m)

tt = (sum / 100) * 1000
print('The severs decryption function cost: ', "{:.3f}".format(tt), ' ms')

# ------------- test sever 1 decryption function time -----
sum = 0
m = randmpz_in(2 ** 12)
for i in range(100):
    sum += pdec1_timetest(m)

tt = (sum / 100) * 1000
print('The sever 1 decryption function cost: ', "{:.3f}".format(tt), ' ms')

# ------------- test sever 2 decryption function time -----
sum = 0
m = randmpz_in(2 ** 12)
for i in range(100):
    sum += pdec2_timetest(m)

tt = (sum / 100) * 1000
print('The sever 2 decryption function cost: ', "{:.3f}".format(tt), ' ms')


# ------------- test ciphertext addition function time -----
sum = 0
m = randmpz_in(2 ** 12)
for i in range(100):
    sum += ciphertext_add_timetest(m)

tt = (sum / 100) * 1000
print('The ciphertext addition function cost: ', "{:.3f}".format(tt), ' ms')

# ------------- test scalar multiplication function time -----
sum = 0
m = randmpz_in(2 ** 12)
for i in range(100):
    sum += scalar_mul_timetest(m)

tt = (sum / 100) * 1000
print('The scalar multiplication function cost: ', "{:.3f}".format(tt), ' ms')

# ------------- test ciphertext subtraction function time -----
sum = 0
m = randmpz_in(2 ** 12)
for i in range(100):
    sum += ciphertext_sub_timetest(m)

tt = (sum / 100) * 1000
print('The ciphertext subtraction function cost: ', "{:.3f}".format(tt), ' ms')