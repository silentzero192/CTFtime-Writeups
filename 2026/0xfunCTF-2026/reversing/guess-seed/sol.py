#!/usr/bin/env python3
import time
import random

# Adjust these to your target window
# Example: last 1 hour
TIME_NOW = int(time.time())
TIME_WINDOW = 3600  # 1 hour (3600 seconds)


def generate_numbers(seed):
    random.seed(seed)
    nums = [random.randint(0, 2**31 - 1) for _ in range(5)]
    # Reduce modulo 1000 as binary does
    reduced = [n % 1000 for n in nums]
    # Combine first two into 64-bit pair
    first_input = (reduced[0] << 32) | reduced[1]
    return [first_input] + reduced[2:]


def main():
    print("[*] Starting seed brute-force...")
    for t in range(TIME_NOW - TIME_WINDOW, TIME_NOW + 1):
        candidate = generate_numbers(t)
        # Print candidate numbers
        print(f"Trying seed {t}: {candidate}")
        # Optional: Check against known numbers if you have them
        # Example: if candidate matches challenge numbers, print flag
        # if candidate[:5] == [known numbers]:
        #     print("Found correct seed!", t)
        #     print("Numbers to input:", candidate)
        #     break

    print("[*] Brute-force done. Pick the correct seed and use numbers above.")


if __name__ == "__main__":
    main()
