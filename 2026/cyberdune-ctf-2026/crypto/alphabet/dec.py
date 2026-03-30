import json

with open("key.json") as f:
    key = json.load(f)

# build reverse mapping
rev = {v: k for k, v in key.items()}

cipher = "NG CT TC AT GN GA CT RR TG GN RR CR NA CC RR NT RR TG GN"

tokens = cipher.split()
plaintext = "".join(rev[t] for t in tokens)

print(f"CYBERDUNE{{{plaintext}}}")
