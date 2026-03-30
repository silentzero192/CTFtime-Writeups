def try_decode(enc, steps):
    res = ""
    i = 0
    pos = 0
    while pos < len(enc):
        if enc[pos] == " ":
            res += " "
            pos += 1
        elif i % steps == 0:
            # ascii is 97–122 → 2 or 3 digits
            for size in (2,3):
                if pos+size <= len(enc):
                    val = enc[pos:pos+size]
                    if val.isdigit():
                        c = int(val)
                        if 97 <= c <= 122:
                            res += chr(c)
                            pos += size
                            break
            else:
                return None
        else:
            res += enc[pos]
            pos += 1
        i += 1
    return res


encoded = "122aza tra108lal101ro 102ili112po 98osc104i c117cin97to 103ubb105o"

for s in range(2,6):
    out = try_decode(encoded, s)
    if out:
        print(s, out)
