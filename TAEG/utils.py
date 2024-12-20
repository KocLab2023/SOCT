import random
import gmpy2


def generate_prime(n_bits):
    """
    Generate random prime (n bits length), with gmpy2.next_prime

    :param n_bits: int
    :return: (mpz) a random prime with n_bits length
    """
    rf = random.SystemRandom()
    r = gmpy2.mpz(rf.getrandbits(n_bits))
    r = gmpy2.bit_set(r, n_bits - 1)
    rand_prime = gmpy2.next_prime(r)

    return rand_prime


def randmpz_in(n):
    """
    Generate a uniformly distributed random integer by gmpy2.mpz_random

    Equals to select an element in Zn

    :param n: mpz
    :return: mpz number between 0 and n-1
    """
    rf = random.SystemRandom()
    rs = gmpy2.random_state(rf.getrandbits(10))
    return gmpy2.mpz_random(rs, n)


def relat_prime_in_set(n):
    """
    Select an element in Zn*, which are relatively prime with n

    :param n: mpz
    :return: y(mpz) in Zn*
    """

    y = randmpz_in(n)
    while gmpy2.gcd(y, n) != 1:
        y = randmpz_in(n)
    return y


def r_divides_p_1_relatprime_div(r_len, p_len):
    """
    Generate two prime (r, p), satisfied (r|p-1), gcd(r, (p-1)/r)=1

    :param r_len: number r bite length
    :param p_len: number p bite length
    :return: r(prime_mpz), p(prime_mpz), satisfy (r|p-1), r divides p-1,
     gcd(r, (p-1)/r)=1
    """
    r = generate_prime(r_len)
    p = 0
    while gmpy2.is_prime(p) == False:
        u = generate_prime(p_len - r_len)
        while gmpy2.gcd(r, u) != 1:
            u = generate_prime(p_len - r_len)
        p = r * 2 * u + 1
    return r, p


def r_divides_p_1(r_len, p_len):
    """
    Generate two prime (r, p), satisfied (r|p-1), don't print in processing

    :param r_len: number r bite length
    :param p_len: number p bite length
    :return: r(prime_mpz), p(prime_mpz), satisfy (r|p-1), r divides p-1
    """
    r = generate_prime(r_len)
    u = generate_prime(p_len - r_len)
    p = r * 2 * u + 1
    while gmpy2.is_prime(p) == False:
        u = generate_prime(p_len - r_len)
        p = r * 2 * u + 1
    return r, p


def r_divides_p_1_proce(r_len, p_len):
    """
    Generate two prime r, p satisfied (r|p-1), print something in processing
    (be good for long generate time)

    :param r_len: number r bite length
    :param p_len: number p bite length
    :return: r(mpz), p(mpz), satisfy (r|p-1), r divides p-1
    """

    i = 0  # not necessary
    list1 = ['(づ｡◕ᴗᴗ◕｡)づ', '(づ｡—ᴗᴗ—｡)づ', '(づ｡◕ᴗᴗ◕｡)づ', '(づ｡—ᴗᴗ—｡)づ',
             '(づ｡◕ᴗᴗ◕｡)づ',
             '(づ｡◕ᴗᴗ◕｡)づ']  # not necessary
    k = 0  # not necessary
    r = generate_prime(r_len)
    u = generate_prime(p_len - r_len)
    p = r * 2 * u + 1

    while gmpy2.is_prime(p) == False:
        u = generate_prime(p_len - r_len)
        p = r * 2 * u + 1
        k += 1
        if k % 4 == 0:  # not necessary
            # print('\r Processing...  %s' , list1[i % len(list1)])
            print('\r Processing...  already tried: %s' % k, ' ' + list1[i % len(list1)], end='')
            i += 1  # not necessary
        if k > 3000:  # not necessary
            r = generate_prime(r_len)  # not necessary

    return r, p


def mulmod(a, b, c):
    """
    Do a * b mod c with gmpy2, where a, b, c are integers.

    :param a: mpz
    :param b: mpz
    :param c: mpz
    :return: (mpz)  a*b (mod c)
    """
    return gmpy2.mod(a * b, c)


'''
# Not Use Yet
def generate_prime_between(n1_bits, n2_bits):
    rf = random.SystemRandom()
    n_bits = random.SystemRandom().randrange(n1_bits, n2_bits)
    r = gmpy2.mpz(rf.getrandbits(n_bits))
    r = gmpy2.bit_set(r, n_bits-1)
    rand_prime = gmpy2.next_prime(r)
    return rand_prime
    
    
def randprime_in(n):
    """
    Uses gmpy2.mpz_random , returns a prime random integer
    :return int: probable prime between 0 and n-1
    """
    rf = random.SystemRandom()
    rs = gmpy2.random_state(rf.getrandbits(10))
    rand_num = gmpy2.mpz_random(rs, n)
    return gmpy2.next_prime(rand_num)
    
    
def lf(x, n):#logistic function   used in paillier
    return (x-1) // n
'''
