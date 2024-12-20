from TAEG import threshold_eigamal as taeg
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



p, q, g = setup_group()
CS1 = sp.CS()
h1 = CS1.gen_keypair(p, q, g)

CS2 = sp.CS()
h2 = CS2.gen_keypair(p, q, g)

pk = taeg.PublicKey(p, q, g, h1, h2)
pk.pre_compute_h(h1, h2, p)
gm_dict = taeg.gen_gm_mapping(g, p)

# ------------set plaintext and encrypt them------------
m1 = 12
m2 = -23
encm1 = taeg.encrypt(m1, pk)
encm2 = taeg.encrypt(m2, pk)

# ----------test and verify the correctness of secure_mul_protocol-------

st = time.perf_counter()
for i in range(1000):
    ct = sp.secure_mul_protocol(encm1, encm2, CS1, CS2, pk, gm_dict)
tt = time.perf_counter() - st
print('The SMUL protocol cost: ', "{:.3f}".format(tt), ' ms')

rec_m = taeg.decrypt(ct, pk, CS1.sk, CS2.sk, gm_dict)
assert rec_m == m1 * m2

# ----------test and verify the correctness of secure_comp_protocol-------
st = time.perf_counter()
for i in range(1000):
    compare_result = sp.secure_comp_protocol(encm1, encm2, CS1, CS2, pk, gm_dict)
tt = time.perf_counter() - st
print('The SCMP protocol cost: ', "{:.3f}".format(tt), ' ms')

rec_m = taeg.decrypt(compare_result[0], pk, CS1.sk, CS2.sk, gm_dict)
if m1 > m2:
    assert rec_m == 0
else:
    assert rec_m == 1

# ----------test and verify the correctness of secure_ssba_protocol-------
st = time.perf_counter()
for i in range(1000):
    enc_sign, ciphertext1 = sp.secure_sba_protocol(encm2, CS1, CS2, pk, gm_dict)
tt = time.perf_counter() - st
print('The SSBA protocol cost: ', "{:.3f}".format(tt), ' ms')

rec_b = taeg.decrypt(enc_sign, pk, CS1.sk, CS2.sk, gm_dict)
if m2 > 0:
    assert rec_b == 0
else:
    assert rec_b == 1
rec_m = taeg.decrypt(ciphertext1, pk, CS1.sk, CS2.sk, gm_dict)
assert rec_m == abs(m2)



pass
