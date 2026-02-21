#!/usr/bin/env python3
from pwn import *
import sys

# LCG parameters
M = 2147483647
A = 48271
C = 12345
invA = pow(A, M - 2, M)  # modular inverse of A modulo M


def recover_next_spins(spins):
    """
    Given 10 consecutive spins (list of ints), compute the next 5 spins.
    """
    # brute-force possible state after 10th spin (state10 % 100 == spins[-1])
    for s10 in range(spins[-1], M, 100):
        state = s10
        valid = True
        # check backwards from spin9 down to spin1
        for i in range(9, 0, -1):
            state = (state - C) * invA % M
            if state % 100 != spins[i - 1]:
                valid = False
                break
        if valid:
            # found correct state10
            curr = s10
            next_spins = []
            for _ in range(5):
                curr = (A * curr + C) % M
                next_spins.append(curr % 100)
            return next_spins
    raise ValueError("No valid state found")


def main():
    if len(sys.argv) > 1:
        host = sys.argv[1]
    else:
        host = "chall.0xfun.org"
    port = 38095

    io = remote(host, port)

    # Read the 10 spin values
    spins = []
    for _ in range(10):
        line = io.recvline().strip().decode()
        if line.isdigit():
            spins.append(int(line))
        else:
            # maybe prompt appears earlier? rare
            break

    # If we didn't get exactly 10 numbers, read more intelligently
    while len(spins) < 10:
        line = io.recvline().strip().decode()
        if line.isdigit():
            spins.append(int(line))

    log.success(f"Received spins: {spins}")

    # Compute next 5 spins
    next_spins = recover_next_spins(spins)
    log.success(f"Predicted next spins: {next_spins}")

    # Send the prediction
    prediction = " ".join(map(str, next_spins))
    io.sendline(prediction)

    # Receive the flag or any further output
    try:
        print(io.recvall(timeout=2).decode())
    except EOFError:
        pass
    io.close()


if __name__ == "__main__":
    main()
