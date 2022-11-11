import random
"""
sieve and millerRabinTest

https://oeis.org/A014233         Smallest odd number for which Miller-Rabin primality test on bases <= n-th prime does not reveal compositeness. 
https://oeis.org/A006945         Smallest odd number that requires n Miller-Rabin primality tests. 
https://oeis.org/A090659         Odd composites with increasing proportion of nontrivial non-witnesses of compositeness by the Miller-Rabin primality test. 
  -> 9080191
https://oeis.org/A340462         Triangular numbers that are the hypotenuse of a primitive Pythagorean triple (PPT) such that another member of the triple is also triangular. 
  -> 4759123141
https://oeis.org/A020287         Strong pseudoprimes to base 61. 
  -> 4759123141

https://oeis.org/A209834 		a(A074773(n) mod 1519829 mod 18) = A074773(n), 1 <= n <= 18. 

https://miller-rabin.appspot.com/

"""

def millerRabinTest(n):
    def get_a_list(n):
        if n < 2047: alist = [2]
        elif n < 1373653: alist = [2, 3]
        #lif n < 9080191: alist = [31, 73]
        elif n < 25326001: alist = [2, 3, 5]
        #lif n < 170584961: alist = [350, 3958281543]
        elif n ==3215031751: alist = [0]          # only exception
        #        4294967296    -- 2^32
        #lif n < 4759123141: alist = [2, 7, 61]
        #lif n < 75792980677: alist = [2, 379215, 457083754]
        elif n < 118670087467: alist = [2, 3, 5, 7]   #  -> n= 3215031751  or prime
        #lif n < 1122004669633: alist = [2, 13, 23, 1662803]
        elif n < 2152302898747: alist = [2, 3, 5, 7, 11]
        elif n < 3474749660383: alist = [2, 3, 5, 7, 11, 13]
        #lif n < 21652684502221: alist = [2, 1215, 34862, 574237825]
        elif n < 341550071728321: alist = [2, 3, 5, 7, 11, 13, 17]
        elif n < 3825123056546413051: alist = [2, 3, 5, 7, 11, 13, 17, 19, 23]
        #        18446744073709551616   -- 2^64
        elif n < 318665857834031151167461: alist = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
        elif n < 3317044064679887385961981: alist = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41]
        #        79228162514264337593543950336   -- 2^96
        #        340282366920938463463374607431768211456  -- 2^128
        else: alist = None

        if alist:
            for a in alist:
                yield a
        else:
            yield 2
            a = 3
            while True:
                yield a
                a += 2


    #  n = 2**r * s + 1,    s%2==1
    #  random 'a'   1<=a<n
    #  test  a**s != 1 ( mod n)  and  a**(2**j * s) != -1 (mod n)   for 0<=j<r     then n is a composite
    def oneTest(a):
        base = n-1
        while base%2==0:
            base //= 2
            if pow(a, base, n) == n-1:
                return True
        if pow(a, base, n) == 1:
            return True

        return False

    if n==2:
        return True
    if n<2:
        return False
    chance = 1
    for a in get_a_list(n):
        if not a:
            return False
        if not oneTest(a):
            return False
        chance *= 4
        if chance > n:
            break
    return True


def nextPrime(num):
    if num<2: return 2
    num |= 1
    while not millerRabinTest(num):
        num += 2
    return num

def prevPrime(num):
    num |= 1
    num -= 2
    while not millerRabinTest(num):
        num -= 2
    return num


def generatePrime(nbits):
    num = random.getrandbits(nbits)
    num |= pow(2, nbits-1)
    return nextPrime(num)

def generatePrimes(start=2, end=None):
    if start<3:
        yield 2
        num = 3
    else:
        num = start
    while end is None or num<end:
        num = nextPrime(num)
        yield num
        num += 2


def sieve(num):
    """
    import primality
    for p in primality.sieve(1000):
        print(p, end=" ")

    """
    map = [False for _ in range(num)]
    p = 2
    while p<num:
        if not map[p]:
            yield p
            for i in range(p*p, num, p):
                map[i]= True
        p += 1

def primesupto(n):
    # https://stackoverflow.com/questions/2068372/fastest-way-to-list-all-primes-below-n-in-python/3035188#3035188
    """ Returns  a list of primes < n """
    sieve = [True] * (n//2)
    for i in range(3,int(n**0.5)+1,2):
        if sieve[i//2]:
            sieve[i*i//2::i] = [False] * ((n-i*i-1)//(2*i)+1)
    return [2] + [2*i+1 for i in range(1,n//2) if sieve[i]]


