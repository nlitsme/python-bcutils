import random

def millerRabinTest(n):
    def get_a_list(n):
        if n < 2047: alist = [2]
        elif n < 1373653: alist = [2, 3]
        elif n < 9080191: alist = [31, 73]
        elif n < 25326001: alist = [2, 3, 5]
        elif n < 3215031751: alist = [2, 3, 5, 7]
        elif n < 4759123141: alist = [2, 7, 61]
        elif n < 1122004669633: alist = [2, 13, 23, 1662803]
        elif n < 2152302898747: alist = [2, 3, 5, 7, 11]
        elif n < 3474749660383: alist = [2, 3, 5, 7, 11, 13]
        elif n < 341550071728321: alist = [2, 3, 5, 7, 11, 13, 17]
        elif n < 3825123056546413051: alist = [2, 3, 5, 7, 11, 13, 17, 19, 23]
        elif n < 18446744073709551616: alist = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
        elif n < 318665857834031151167461: alist = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
        elif n < 3317044064679887385961981: alist = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41]
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
        if not oneTest(a):
            return False
        chance *= 4
        if chance > n:
            break
    return True

def nextPrime(num):
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

