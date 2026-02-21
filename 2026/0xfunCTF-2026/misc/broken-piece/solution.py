from PIL import Image
import numpy as np
from pyzbar.pyzbar import decode
import sys


def decode_qr(image):
    """Decode QR code from a PIL image, return decoded string or None."""
    # Convert to grayscale if needed
    if image.mode != "L":
        image = image.convert("L")
    # Binarize (optional, but helps)
    # We'll use the raw image as pyzbar handles thresholding
    decoded = decode(image)
    if decoded:
        return decoded[0].data.decode("utf-8")
    return None


def main():
    gif_path = "qr.gif"
    try:
        gif = Image.open(gif_path)
    except Exception as e:
        print(f"Error opening {gif_path}: {e}")
        return

    frames = []
    try:
        while True:
            frames.append(gif.copy().convert("L"))  # store as grayscale
            gif.seek(gif.tell() + 1)
    except EOFError:
        pass

    print(f"Extracted {len(frames)} frames.")

    # First try decoding each frame individually
    for i, frame in enumerate(frames):
        result = decode_qr(frame)
        if result:
            print(f"Frame {i} decoded: {result}")
            print(f"Flag: 0xfun{{{result}}}")
            return

    # If no single frame works, combine them
    print("No single frame decodes. Combining frames...")
    # Stack frames into a 3D array (frames, height, width)
    arr = np.stack([np.array(frame) for frame in frames], axis=0)
    # Take minimum across frames (black=0, white=255) to get union of black pixels
    combined = np.min(arr, axis=0).astype(np.uint8)
    combined_img = Image.fromarray(combined)
    combined_img.save("combined.png")
    print("Saved combined image as 'combined.png'.")

    result = decode_qr(combined_img)
    if result:
        print(f"Combined image decoded: {result}")
        print(f"Flag: 0xfun{{{result}}}")
    else:
        print("Still no QR code detected. Try manual inspection of 'combined.png'.")


if __name__ == "__main__":
    main()
