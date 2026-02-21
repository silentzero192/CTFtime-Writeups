from quantcrypt.kem import MLKEM_1024
from quantcrypt.cipher import KryptonKEM
from pathlib import *

kem = MLKEM_1024()
kry = KryptonKEM(MLKEM_1024)

sk_size = 3168

data = []

with open("output.raw", "rb") as f:
    file_data = f.read()

# total number of secret keys inside file
total_keys = len(file_data) // sk_size

for i in range(total_keys):
    start = len(file_data) - (i + 1) * sk_size
    end = len(file_data) - i * sk_size
    chunk = file_data[start:end]
    data.append(chunk)

print(f"Total keys extracted: {len(data)}")

file_name = 22
ct = Path(f"./flag_22.enc")
pt = Path(f"./encrypted_{file_name}.enc")

for i in range(40):
    try:
        kry.decrypt_to_file(data[i], ct, pt)
        print(
            f"[+] Successfully decrypted layer ./encrypted_{file_name}.enc with key at index {i}"
        )
        ct = pt
        file_name -= 1
        pt = Path(f"./encrypted_{file_name}.enc")
        if file_name == 0:
            pt = Path("./flag.png")
    except Exception:
        continue

print(f"[+] Final decryption successful! Flag saved as flag.png")

for file in Path(".").glob("encrypted_*.enc"):
    file.unlink()

print("[+] All intermediate encrypted files removed.")
