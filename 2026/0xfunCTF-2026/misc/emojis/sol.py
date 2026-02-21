# sol.py
# Emoji decoder for 0xfun CTF challenge

# Read the emoji file
with open("emoji.txt", "r", encoding="utf-8") as f:
    data = f.read().strip()

# Convert each emoji to a codepoint
codepoints = [ord(c) for c in data]

# Map codepoints to ASCII characters
# Most misc emoji CTFs work with mod 256
flag_chars = [chr(cp % 256) for cp in codepoints]

# Join and format as the flag
flag = "0xfun{" + "".join(flag_chars) + "}"
print("Recovered flag:")
print(flag)
