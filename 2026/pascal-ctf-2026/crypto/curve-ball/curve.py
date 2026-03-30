#!/usr/bin/env python3
from Crypto.Util.number import bytes_to_long, inverse
import os

p = 1844669347765474229
a = 0
b = 1
n = 1844669347765474230
Gx = 27
Gy = 728430165157041631

FLAG = os.environ.get('FLAG', 'pascalCTF{REDACTED}')

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y
    
    def __add__(self, other):
        if self.x is None:
            return other
        if other.x is None:
            return self
        
        if self.x == other.x and self.y == (-other.y % p):
            return Point(None, None)
        if self.x == other.x:
            s = (3 * self.x**2 + a) * inverse(2 * self.y, p) % p
        else:
            s = (other.y - self.y) * inverse(other.x - self.x, p) % p
            
        x3 = (s*s - self.x - other.x) % p
        y3 = (s * (self.x - x3) - self.y) % p
        return Point(x3, y3)
    
    def __rmul__(self, scalar):
        result = Point(None, None)
        addend = self
        while scalar:
            if scalar & 1:
                result = result + addend
            addend = addend + addend
            scalar >>= 1
        return result

def main():
    secret = bytes_to_long(os.urandom(8)) % n
    G = Point(Gx, Gy)
    Q = secret * G
    
    print("Curve Ball")
    print(f"y^2 = x^3 + 1 (mod {p})")
    print(f"n = {n}")
    print(f"G = ({Gx}, {Gy})")
    print(f"Q = ({Q.x}, {Q.y})\n")
    
    while True:
        print("1. Guess secret")
        print("2. Compute k * P")
        print("3. Exit")
        choice = input("> ").strip()
        
        if choice == '1':
            try:
                guess = input("secret (hex): ").strip()
                if guess.startswith('0x'):
                    guess = guess[2:]
                guess = int(guess, 16)
                if guess == secret:
                    print(f"Flag: {FLAG}")
                    break
                else:
                    print("Wrong.\n")
            except:
                print("Invalid.\n")
        
        elif choice == '2':
            try:
                k = int(input("k: ").strip())
                pt = input("P (G/Q/x,y): ").strip()
                if pt.upper() == 'G':
                    P = G
                elif pt.upper() == 'Q':
                    P = Q
                else:
                    x, y = pt.replace('(','').replace(')','').split(',')
                    P = Point(int(x), int(y))
                R = k * P
                if R.x is None:
                    print("Result: O (infinity)\n")
                else:
                    print(f"Result: ({R.x}, {R.y})\n")
            except:
                print("Invalid.\n")
        
        elif choice == '3':
            break

if __name__ == "__main__":
    main()