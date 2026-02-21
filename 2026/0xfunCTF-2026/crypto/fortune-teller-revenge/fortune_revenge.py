#!/usr/bin/env python3

import random

class FortuneTellerRevenge:
    M = 2**64
    A = 2862933555777941757
    C = 3037000493

    JUMP = 100000
    A_JUMP = pow(A, JUMP, M)
    C_JUMP = 8391006422427229792

    def __init__(self, seed=None):
        self.state = seed if seed is not None else random.randint(1, self.M - 1)

    def next(self):
        self.state = (self.A * self.state + self.C) % self.M
        return self.state

    def jump(self):
        self.state = (self.A_JUMP * self.state + self.C_JUMP) % self.M

    def glimpse(self):
        full = self.next()
        return full >> 32


if __name__ == "__main__":
    ft = FortuneTellerRevenge()

    g1 = ft.glimpse()
    print(f"{g1}")

    ft.jump()
    g2 = ft.glimpse()
    print(f"{g2}")

    ft.jump()
    g3 = ft.glimpse()
    print(f"{g3}")
