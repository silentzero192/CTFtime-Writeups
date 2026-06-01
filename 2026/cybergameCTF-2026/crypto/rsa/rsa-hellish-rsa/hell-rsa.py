import secrets
from Crypto.Util.number import isPrime, bytes_to_long

HELL_VALUE = (().__class__.__mro__.index(object))

MESSAGE = (b"") # u have to figure this on your own.
e = bytes_to_long(MESSAGE)

sins = 4096
first_devil = (lambda s: next(x for x in iter(lambda: secrets.randbits(s) | (HELL_VALUE << (s - HELL_VALUE)) | HELL_VALUE, None) if isPrime(x)))(sins)
second_devil = max(3, (max(HELL_VALUE, e.bit_length()) + sins - HELL_VALUE) // sins + 2)

n = pow(first_devil, second_devil)

demon = secrets.randbelow(first_devil - HELL_VALUE + HELL_VALUE)
m = (HELL_VALUE + demon * first_devil) % n

# RSA encryption
c = pow(m, e, n)

# this is everything that Hell offers
print("n =", hex(n))
print("e =", hex(e))
print("c =", hex(c))