#!/usr/bin/env sage
import sys
import itertools
from sage.all import *

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------
R = RealField(256)
phi = R((1 + sqrt(5)) / 2)  # Golden ratio

masked = "?7086013?3756162?51694057?5285516?54803756?9202316?39221780?4895755?50591029"


# ------------------------------------------------------------
# 1. Mathematical Analysis - Determine Decimal Point Position
# ------------------------------------------------------------
def estimate_decimal_position():
    """Estimate where the decimal point should be based on spiral properties."""
    # The spiral function transforms x (0 < x < 1) to y
    # Let's estimate the range of y for x in (0, 1)

    # For small x (close to 0), the spiral output is approximately phi
    # For x = 0, spiral would give approximately phi after many iterations
    # Actually, let's test a few values

    # We know from the challenge that flag has format "0xL4ugh{...}"
    # The integer value of this prefix is about 26 digits
    # x = flag_int / 10^flen where flen ≈ 77-78
    # So x is roughly 0.2 to 0.9

    # Let's compute spiral(0.2) and spiral(0.9) to see range
    def quick_spiral(x_val, iterations=10):  # Use fewer iterations for speed
        x = R(x_val)
        for i in range(iterations):
            r = R(i) / R(iterations)
            x = r * sqrt(x * x + 1) + (1 - r) * (x + phi)
        return x

    # Test values
    y_low = quick_spiral(0.1, 81)
    y_high = quick_spiral(0.9, 81)

    print(f"Estimated y range: {y_low:.10f} to {y_high:.10f}")

    # The masked string has 76 digits, so y should be around 66-67
    # This means the decimal point should be after 2 digits
    return 2  # Decimal after 2 digits


# ------------------------------------------------------------
# 2. Generate Candidate Strings
# ------------------------------------------------------------
def generate_candidates():
    """Generate candidate digit strings based on mathematical constraints."""
    n = len(masked)
    k = masked.count("?")

    print(f"Total length: {n}, Missing digits: {k}")

    # Position analysis: the first '?' is at position 0
    # Since y is around 66-67, the first digit must be '6'

    # List of positions of '?'
    mask_positions = [i for i, c in enumerate(masked) if c == "?"]
    print(f"Mask positions: {mask_positions}")

    # Generate combinations - but let's be smart
    # We know the output format suggests certain constraints

    # The first missing digit (position 0) is likely '6' or '7'
    # Let's try both
    candidates = []

    for first_digit in ["6", "7"]:
        # Generate all combinations for remaining 8 positions
        for combo in itertools.product("0123456789", repeat=8):
            # Build the string
            s_list = list(masked)
            digit_idx = 0
            for pos in mask_positions:
                if digit_idx == 0:
                    s_list[pos] = first_digit
                else:
                    s_list[pos] = combo[digit_idx - 1]
                digit_idx += 1

            candidates.append("".join(s_list))

    return candidates, mask_positions


# ------------------------------------------------------------
# 3. Inverse Spiral Function (Optimized)
# ------------------------------------------------------------
def inverse_spiral_optimized(y, max_iter=1000):
    """Invert the spiral transformation using Newton's method."""
    # Use Newton's method to solve for x

    # Define the function and its derivative
    def f(x_val):
        # Forward spiral
        x = R(x_val)
        for i in range(81):
            r = R(i) / R(81)
            x = r * sqrt(x * x + 1) + (1 - r) * (x + phi)
        return x - y

    def df(x_val):
        # Numerical derivative
        h = R(1e-10)
        return (f(x_val + h) - f(x_val - h)) / (2 * h)

    # Initial guess: since y is around 66-67, and x is between 0 and 1
    # We can make an educated guess
    # The spiral function is roughly linear: y ≈ a*x + b
    # Let's estimate a and b by testing two points

    x_test1 = R(0.5)
    y_test1 = f(x_test1) + y  # Actually get forward spiral

    x_test2 = R(0.6)
    y_test2 = f(x_test2) + y

    # Linear approximation: y = m*x + c
    m = (y_test2 - y_test1) / (x_test2 - x_test1)
    c = y_test1 - m * x_test1

    # Solve for x: y_target = m*x + c  => x = (y_target - c)/m
    x_guess = (y - c) / m

    # Ensure x_guess is in (0, 1)
    x_guess = max(min(x_guess, R(0.99)), R(0.01))

    # Newton's method
    x_current = x_guess
    for _ in range(max_iter):
        fx = f(x_current)
        if abs(fx) < 1e-15:
            break
        dfx = df(x_current)
        if dfx == 0:
            break
        x_next = x_current - fx / dfx

        # Keep x in reasonable bounds
        if x_next <= 0 or x_next >= 1:
            x_next = x_current / 2  # Backup strategy

        if abs(x_next - x_current) < 1e-30:
            break

        x_current = x_next

    return x_current


# ------------------------------------------------------------
# 4. Check Flag Validity
# ------------------------------------------------------------
def is_valid_flag(flag_int):
    """Check if an integer corresponds to a valid flag."""
    try:
        from Crypto.Util.number import long_to_bytes

        # Convert to bytes
        flag_bytes = long_to_bytes(flag_int)

        # Check length (should be around 32 bytes)
        if len(flag_bytes) > 40 or len(flag_bytes) < 20:
            return False, None

        # Check format: starts with b'0xL4ugh{' and ends with b'}'
        if not flag_bytes.startswith(b"0xL4ugh{"):
            return False, None

        if not flag_bytes.endswith(b"}"):
            return False, None

        # Check all bytes are printable ASCII
        if all(32 <= b <= 126 for b in flag_bytes):
            return True, flag_bytes.decode()
        else:
            return False, None

    except Exception as e:
        return False, None


# ------------------------------------------------------------
# 5. Main Solution
# ------------------------------------------------------------
def main():
    print("Solving Spiral Floats Challenge...")
    print("=" * 60)

    # Step 1: Estimate decimal position
    decimal_pos = estimate_decimal_position()
    print(f"Estimated decimal position: after {decimal_pos} digits")

    # Step 2: Generate candidate strings
    candidates, mask_positions = generate_candidates()
    print(f"Generated {len(candidates)} candidate strings")

    # Step 3: Try each candidate
    found_flags = []

    for idx, candidate in enumerate(candidates):
        if idx % 10000 == 0 and idx > 0:
            print(f"Processed {idx}/{len(candidates)} candidates...")

        # Insert decimal point
        y_str = candidate[:decimal_pos] + "." + candidate[decimal_pos:]

        try:
            y = R(y_str)
        except:
            continue

        # Invert spiral to get x
        x = inverse_spiral_optimized(y)

        if x <= 0 or x >= 1:
            continue

        # Try different flen values
        for flen in range(75, 80):
            flag_int = round(x * R(10) ** flen)

            # Quick checks
            if flag_int < 10**70:  # Too small for a flag
                continue

            # Check flag validity
            valid, flag_str = is_valid_flag(int(flag_int))
            if valid:
                found_flags.append(flag_str)
                print(f"\nFound potential flag: {flag_str}")

    # Step 4: Display results
    print("\n" + "=" * 60)
    if found_flags:
        print("FLAGS FOUND:")
        for flag in set(found_flags):
            print(f"  {flag}")
    else:
        print("No flags found. Trying alternative approach...")

        # Alternative: Use the fact that flag has specific format
        # Let's try to solve using the known prefix/suffix constraints
        print("\nTrying format-based recovery...")

        # The flag format is: 0xL4ugh{...}
        # Let's represent this as bytes and work backwards

        # We know the spiral output y is 76 digits
        # Let's try to find x such that when converted to flag, it matches format

        # Create a more targeted search
        target_prefix = b"0xL4ugh{"
        target_suffix = b"}"

        # Convert prefix to integer part of the flag
        from Crypto.Util.number import bytes_to_long

        prefix_int = bytes_to_long(target_prefix)
        suffix_int = ord(target_suffix)

        # The flag integer has structure: prefix * 256^k + middle + suffix
        # We need to find the right x

        # Let's try a different approach: binary search for x
        print("Performing binary search for x...")

        def check_x(x_test):
            """Check if x produces a valid flag."""
            # Try different flen values
            for flen in [77, 78]:
                flag_int = round(x_test * R(10) ** flen)

                # Convert to bytes
                try:
                    flag_bytes = long_to_bytes(int(flag_int))
                    if (
                        len(flag_bytes) >= 8
                        and flag_bytes.startswith(target_prefix)
                        and flag_bytes.endswith(target_suffix)
                    ):
                        # Check if all bytes are printable
                        if all(32 <= b <= 126 for b in flag_bytes):
                            return True, flag_bytes.decode()
                except:
                    pass
            return False, None

        # Binary search in (0, 1) for x
        left, right = R(0.1), R(0.9)
        for _ in range(50):  # 50 iterations of binary search
            mid = (left + right) / 2

            # Compute y for this x
            y_test = spiral(mid, phi)
            y_str = str(y_test).replace(".", "")

            # Compare with masked string (allowing for '?' positions)
            match = True
            for i, c in enumerate(masked):
                if c != "?" and i < len(y_str) and c != y_str[i]:
                    match = False
                    break

            if match:
                # Check if this x gives a valid flag
                valid, flag_str = check_x(mid)
                if valid:
                    print(f"\nFound flag via binary search: {flag_str}")
                    return

            # Adjust search bounds based on comparison
            # This is heuristic - we compare the known digits
            known_match_count = 0
            for i, c in enumerate(masked):
                if c != "?" and i < len(y_str) and c == y_str[i]:
                    known_match_count += 1

            # If many known digits match, we might be close
            if known_match_count > 60:  # Most known digits match
                # Try nearby values
                for offset in [R(-0.01), R(0), R(0.01)]:
                    x_test = mid + offset
                    if x_test > 0 and x_test < 1:
                        valid, flag_str = check_x(x_test)
                        if valid:
                            print(f"\nFound flag via local search: {flag_str}")
                            return

            # Adjust binary search (heuristic)
            # Compare the generated y with masked string
            # We need a better metric - but for now, just continue

        print("Binary search did not find the flag.")

    print("=" * 60)


# ------------------------------------------------------------
# 6. Run the solution
# ------------------------------------------------------------
if __name__ == "__main__":
    main()
