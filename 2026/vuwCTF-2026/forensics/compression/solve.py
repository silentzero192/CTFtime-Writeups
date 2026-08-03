def decompress_rle(input_file, output_file):
    with open(input_file, "rb") as f:
        data = f.read()

    decompressed = []

    # Iterate through the binary data 2 bytes at a time: [count, character]
    for i in range(0, len(data) - 1, 2):
        count = data[i]
        # Decode the character byte as ASCII (using replacement if unprintable)
        char = chr(data[i + 1])
        decompressed.append(char * count)

    result = "".join(decompressed)

    # Save the expanded text
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(result)

    print(f"[+] Decompressed output written to {output_file}")


if __name__ == "__main__":
    decompress_rle("compressed.dat", "decompressed.txt")
