from TAEG import threshold_eigamal as taeg
from gmpy2 import mpz, powmod, invert
import time

def writting_group_tofile(path):
    # ----------writing data to files, notice the existing file
    file = open(path + "g2048.txt", 'w')  # Open file EIGamal_group_g.txt containing generator g
    file.write(str(g))  # write g to file
    file.close()  # Close the file
    file = open(path + "p2048.txt", 'w')  # Open file EIGamal_group_p.txt containing prime modulus p
    file.write(str(p))  # write p to file
    file.close()  # Close the file
    file = open(path + "q2048.txt", 'w')  # Open file EIGamal_group_q.txt containing prime order q
    file.write(str(q))  # write q to file
    file.close()  # Close the file
    print('Successfully written to file! ')


# -------generate and write group parameters (p,q,g) to files------
st = time.perf_counter()
p, q, g = taeg.generate_group()
et = time.perf_counter()
print('key generation cost:', et - st, ' s')

# path = 'group parameters/'
# writting_group_tofile(path)






# Processing...  already tried: 392  (づ｡—ᴗᴗ—｡)づkey generation cost: 74.83929150001495  s