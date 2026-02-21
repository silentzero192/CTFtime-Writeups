# CTF Writeup

**Challenge Name:** Blitz Traffic  
**Platform:** Blitz CTF 2025
**Category:** Forensics  
**Difficulty:** Easy  
**Time Spent:** ~20 minutes  

---

## 1) Goal (What was the task?)

The challenge description said:  
> “some kind of figure is out there. Probably Now Grab the flag. you know what to do.”

We were given a password-protected ZIP file.  
The goal was to extract its contents, analyze the data, and recover the flag hidden inside.

Success criteria: Find the flag in the format `Blitz{...}`.

---

## 2) Key Clues (What mattered?)

- File provided: `protected.zip`
- It was password protected
- Running `strings` on the ZIP file revealed readable text
- Extracted file name: `blitzhack_traffic.pcap`
- PCAP file → indicates network traffic analysis
- Description hint: “figure is out there” → suggests an image hidden in traffic

---

## 3) Plan (Your first logical approach)

- Since the ZIP was password-protected, first attempt was to inspect it using `strings`.
- If password is weak or embedded, it may appear in raw strings.
- After extraction, analyze the `.pcap` file for transferred files (likely an image).
- Reconstruct any file data from TCP payloads.

---

## 4) Steps (Clean execution)

### Step 1: Inspect the ZIP file

```bash
ls
file protected.zip
```

Confirmed it was a ZIP archive.

---

### Step 2: Extract password using `strings`

```bash
strings protected.zip
```

Among the output, the password was visible:

```
passwd is iloveblitzhack
```

This indicates weak ZIP encryption where metadata is exposed.

---

### Step 3: Extract the ZIP file

```bash
unzip protected.zip
```

Entered password:

```
iloveblitzhack
```

This extracted:

```
blitzhack_traffic.pcap
```

---

### Step 4: Analyze PCAP file

Since the challenge hinted at a “figure”, I suspected an image file was transmitted over the network.

Instead of manually reconstructing via Wireshark, I extracted all TCP payloads using Scapy.

### Recovery Script

```python
from scapy.all import *

packets = rdpcap("blitzhack_traffic.pcap")

# Collect all TCP payloads
payloads = [
    pkt[Raw].load
    for pkt in packets
    if pkt.haslayer(TCP) and pkt.haslayer(Raw)
]

# Write to PNG if data exists
if payloads:
    with open("recovered_secret.png", "wb") as f:
        f.write(b"".join(payloads))
    print("PNG file recovered successfully!")
else:
    print("No payloads found.")
```

---

### Step 5: View the recovered image

The script generated:

```
recovered_secret.png
```

Opening the image revealed the flag.

---

## 5) Solution Summary (What worked and why?)

The ZIP file used weak password protection, and the password was exposed via `strings`.  

After extraction, the PCAP file contained raw TCP traffic. The image (PNG) had been transmitted over the network. By collecting and concatenating all TCP payloads, the original PNG file was reconstructed.

The key idea:
- Extract password from ZIP metadata  
- Reassemble transmitted file from network traffic  

---

## 6) Flag

```
Blitz{H3r3_1S_th3_flAG_G00d_B03}
```

---

## 7) Lessons Learned

- Always run `strings` on password-protected ZIP files in CTFs.
- PCAP files often contain transferred files (images, ZIPs, etc.).
- TCP payload reconstruction is a common forensic technique.
- Challenge descriptions often hint at the hidden file type.

---

## 8) Personal Cheat Sheet

- `strings file.zip` → Check for embedded passwords  
- `unzip file.zip` → Extract archive  
- `.pcap` → Analyze network traffic  
- ```Scapy``` → Extract and reconstruct TCP payload data  
- ```Forensics rule``` → If hint says “figure”, check for image files  
