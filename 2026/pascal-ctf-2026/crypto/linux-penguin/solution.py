from pwn import *

# Remote config
HOST = "penguin.ctf.pascalctf.it"
PORT = 5003

# Known wordlist
words = [
    "biocompatibility",
    "biodegradability",
    "characterization",
    "contraindication",
    "counterbalancing",
    "counterintuitive",
    "decentralization",
    "disproportionate",
    "electrochemistry",
    "electromagnetism",
    "environmentalist",
    "internationality",
    "internationalism",
    "institutionalize",
    "microlithography",
    "microphotography",
    "misappropriation",
    "mischaracterized",
    "miscommunication",
    "misunderstanding",
    "photolithography",
    "phonocardiograph",
    "psychophysiology",
    "rationalizations",
    "representational",
    "responsibilities",
    "transcontinental",
    "unconstitutional",
]

# Start remote connection
io = remote(HOST, PORT)

# Read ASCII art + welcome
io.recvuntil(b"max 16 chars):")

cipher_map = {}

# 1️⃣ Build ECB codebook using oracle (4 words at a time)
for i in range(0, len(words), 4):
    chunk = words[i : i + 4]

    for idx, word in enumerate(chunk):
        io.sendlineafter(f"Word {idx+1}: ".encode(), word.encode())

    # Receive encrypted output
    line = io.recvline().decode().strip()
    enc_words = line.split(": ")[1].split()

    for w, c in zip(chunk, enc_words):
        cipher_map[c] = w

    io.recvuntil(b"max 16 chars):")

log.success(f"Collected {len(cipher_map)} ciphertext mappings")

# 2️⃣ Exit oracle phase (send empty word)
io.sendlineafter(b"Word 1: ", b"")

# 3️⃣ Receive final ciphertext
io.recvuntil(b"Ciphertext:")
ciphertext_line = io.recvline().decode().strip()
target_blocks = ciphertext_line.split()

log.info("Target Ciphertext Blocks:")
for c in target_blocks:
    log.info(c)

# 4️⃣ Recover secret words
recovered_words = [cipher_map[c] for c in target_blocks]

log.success("Recovered Words:")
for w in recovered_words:
    log.success(w)

# 5️⃣ Send guesses
for i, w in enumerate(recovered_words):
    io.sendlineafter(f"Guess the word {i+1}: ".encode(), w.encode())

# 6️⃣ Get flag
io.interactive()
