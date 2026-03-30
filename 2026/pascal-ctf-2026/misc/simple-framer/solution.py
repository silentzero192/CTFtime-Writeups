from PIL import Image


def generate_border_coordinates(width, height):
    coords = []

    for x in range(width):
        coords.append((x, 0))
    for y in range(1, height - 1):
        coords.append((width - 1, y))
    for x in range(width - 1, -1, -1):
        coords.append((x, height - 1))
    for y in range(height - 2, 0, -1):
        coords.append((0, y))

    return coords


def extract_bits(image_path):
    img = Image.open(image_path).convert("RGB")
    w, h = img.size

    border = generate_border_coordinates(w, h)
    bits = ""

    for x, y in border:
        r, g, b = img.getpixel((x, y))
        # brightness-based decision
        bits += "1" if (r + g + b) > 100 else "0"

    return bits


def bits_to_string(bits):
    msg = ""
    for i in range(0, len(bits), 8):
        byte = bits[i : i + 8]
        if len(byte) < 8:
            break

        # reverse bit order (LSB-first handling)
        # byte = byte[::-1]
        msg += chr(int(byte, 2))

    return msg


if __name__ == "__main__":
    bits = extract_bits("output.jpg")
    message = bits_to_string(bits)
    print(message)
