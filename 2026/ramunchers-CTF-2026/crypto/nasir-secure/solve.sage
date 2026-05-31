from Crypto.Util.number import long_to_bytes, bytes_to_long

n = 98237543086838092972727647602649684412823690703586018468107564793518052420849467378972960087089904634059300894743876081610848224988135902506827923518956599452500642947331481355296570045228580344605876571313298325475476590965722009164468025644000368474389606511878244554300783192096414689616993763058583937333
e = 3
c1 = 10014749067983552801777308442259360701131069253434425322498731759314630313146300050356987559850355269257216025931575623364251535349426572721190934970466052609892864
c2 = 788333017013282582064102996912544428368918059912083172803001714562442559798914489707221771582656784173467830862787901677858526810864572559845148224601602432125

a = 70
b = 2706420314
c = 3
d = 2929618574

# Try integer cube root first
def iroot(n, k):
    hi = 1
    while hi ** k < n:
        hi *= 2
    lo = hi // 2
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if mid ** k < n:
            lo = mid
        else:
            hi = mid
    if hi ** k == n:
        return hi
    elif lo ** k == n:
        return lo
    return None

m1_candidate = iroot(c1, 3)
if m1_candidate:
    print(f"Found integer cube root for c1: m1 = {m1_candidate}")
    # m1 = a*m + b, so m = (m1 - b) / a
    m = (m1_candidate - b) // a
    if a * m + b == m1_candidate:
        print(f"m = {m}")
        flag = long_to_bytes(m)
        print(f"Flag: {flag}")
    else:
        print("Division not exact, trying mod n")
        # Try modular inverse
        from Crypto.Util.number import inverse
        m_mod = (m1_candidate - b) * inverse(a, n) % n
        print(f"m (mod n) = {m_mod}")
        flag = long_to_bytes(m_mod)
        print(f"Flag: {flag}")
else:
    print("No integer cube root for c1")

print()

m2_candidate = iroot(c2, 3)
if m2_candidate:
    print(f"Found integer cube root for c2: m2 = {m2_candidate}")
    m = (m2_candidate - d) // c
    if c * m + d == m2_candidate:
        print(f"m = {m}")
        flag = long_to_bytes(m)
        print(f"Flag: {flag}")
    else:
        print("Division not exact, trying mod n")
        from Crypto.Util.number import inverse
        m_mod = (m2_candidate - d) * inverse(c, n) % n
        print(f"m (mod n) = {m_mod}")
        flag = long_to_bytes(m_mod)
        print(f"Flag: {flag}")
else:
    print("No integer cube root for c2")
