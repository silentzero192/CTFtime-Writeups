from elftools.elf.elffile import ELFFile

with open('/home/claude/lisan_switchboard/rune_switchboard', 'rb') as f:
    elf = ELFFile(f)
    rodata = elf.get_section_by_name('.rodata')
    data = bytearray(rodata.data())
    base = rodata['sh_addr']

key_off    = 0x2080 - base
tableA_off = 0x2105 - base
tableB_off = 0x2205 - base

key    = data[key_off   : key_off   + 32]
tableA = data[tableA_off: tableA_off + 256]
tableB = data[tableB_off: tableB_off + 48]

# idx = ((key[i%32] ^ input[i]) + ecx) & 0xFF  — note: XOR first, THEN add
# Python operator precedence bug fix: use parentheses correctly

flag_chars = []
for i in range(48):
    ecx = 31 + 17 * i
    target = tableB[i]
    k = key[i % 32]
    found = []
    for c in range(32, 127):
        idx = ((k ^ c) + ecx) & 0xFF   # XOR before ADD
        if tableA[idx] == target:
            found.append(chr(c))
    flag_chars.append(found)

flag = ''.join(c[0] if c else '?' for c in flag_chars)
print(f"Recovered flag: {flag}")

# Verify by running the binary
import subprocess
result = subprocess.run(
    ['/home/claude/lisan_switchboard/rune_switchboard', flag],
    capture_output=True, text=True
)
print(f"Binary says: {result.stdout.strip()}")
