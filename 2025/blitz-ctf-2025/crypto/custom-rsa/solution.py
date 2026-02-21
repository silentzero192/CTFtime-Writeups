from Crypto.Util.number import *
from sympy.ntheory.modular import crt
from primefac import primefac

# ------------------ Given Parameters ------------------

# Hints to recover p
hint1 = 154888122383146971967744398191123189212  # p % x
hint2 = 130654136341446094800376989317102537325  # p % z

# Public values
n = 1291778230841963634710522186531131140292748304311790700929719174642140386189828346122801056721461179519840234314280632436994655344881023892312594913853574461748121277453328656446109784054563731
e = 9397905637403387422411461938505089525132522490010480161341814566119369497062528168320590767152928258571447916140517
c = 482782367816881259357312883356702175242817718119063880833819462767226937212873552015335218158868462980872863563953024168114906381978834311555560455076311389674805493391941801398577027462103318

# As y is common factor in n and e so we can derive it
# y = GCD(n, e)

y = 215200262830198930084990116270235828097

# As e = x * y * z, then xz = e // y
# find factors of xz using python primefac library

# xz = e // y
# x, z = list(primefac(xz))
x = 205985756524450894105569840071389752521
z = 212007435030018912792096086712981924541

# Use CRT to compute p mod (x*z)
moduli = [x, z]
remainders = [hint1, hint2]
p_mod_xz, _ = crt(moduli, remainders)  # returns (solution, lcm)

# Brute-force valid p from p ≡ p_mod_xz (mod x*z)
M = x * z
p = None
for k in range(1000):  # Try a few candidates
    candidate = p_mod_xz + k * M
    if isPrime(candidate) and n % (candidate * y) == 0:
        p = candidate
        break

if p is None:
    raise ValueError("Could not find valid prime p")


q = n // (p * y)

phi = (p - 1) * (q - 1) * (y - 1)
d = inverse(e, phi)

pt = pow(c, d, n)
print("[+] Flag:", long_to_bytes(pt).decode())
