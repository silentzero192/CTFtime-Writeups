ciphertext = "IisYXH{IisYXH{oaF_dI_Zi_OsceR_QiE_lzouRrm_"
plaintext  = "VuwCTF{"

key = []
for c, p in zip(ciphertext, plaintext):
    if c.isalpha() and p.isalpha():
        c_val = ord(c.upper()) - ord('A')
        p_val = ord(p.upper()) - ord('A')
        k_val = (c_val - p_val) % 26
        key.append(chr(k_val + ord('A')))

print("Derived Key Prefix:", "".join(key))
# Output: NOWWEC
