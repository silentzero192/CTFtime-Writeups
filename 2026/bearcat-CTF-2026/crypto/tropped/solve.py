import json

def solve():
    with open("output.txt", "r") as f:
        lines = f.read().strip().split("\n")

    M = json.loads(lines[0])["M"]
    n = len(M)

    entries = []
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        entries.append(json.loads(line))

    flag = ""

    for entry in entries:
        aM_row = entry["aM"][0]          # 1x64 row vector
        Mb_flat = [entry["Mb"][k][0] for k in range(n)]  # 64 values
        enc_char = entry["enc_char"]

        # Recover b using the tropical max-residuation (lower bound):
        # b_lower[k] = max_i(Mb[i] - M[i][k])
        # This is the LARGEST b such that M ⊗ b_lower ≤ Mb element-wise,
        # and it turns out this gives the exact aMb value.
        b_lower = [max(Mb_flat[i] - M[i][k] for i in range(n)) for k in range(n)]

        # Compute shared secret: aMb = min_k(aM[k] + b_lower[k])
        aMb_val = min(aM_row[k] + b_lower[k] for k in range(n))

        # Decrypt
        pt_char = chr((aMb_val % 32) ^ ord(enc_char))
        flag += pt_char

    print("Flag:", flag)

if __name__ == "__main__":
    solve()
