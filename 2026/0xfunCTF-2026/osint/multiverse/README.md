# Multiverse (OSINT) — 0xfun CTF 2026

## Challenge Overview
The objective of this challenge was to uncover hidden flag fragments by performing OSINT on the username **Massive-Equipment393** and pivoting across different platforms. The investigation required username enumeration, encoded string analysis, and metadata extraction from playlists.

---

## Step 1 — Username Enumeration

The investigation began by searching the username **Massive-Equipment393** using WhatsMyName.

Tool used:
- https://whatsmyname.app

The search revealed a linked Reddit profile associated with the username.

Inside the Reddit profile, I discovered the following encoded string:

```
49Rak48kGp7nJoUq9ofCX
```

This string was encoded using **Base58**.

### Decoding:

```
Base58 Decode:
49Rak48kGp7nJoUq9ofCX
→ pl4yl1st_3xt3nd
```

This provided the middle segment of the flag.

---

## Step 2 — Pivot to Spotify

From the Reddit profile, I navigated to the linked Spotify profile.

On the Spotify account, three public playlists were available.

Inside **Playlist 1**, I found another encoded string:

```
MHhmdW57c3AwdDFmeV8=
```

This string was encoded using **Base64**.

### Decoding:

```
Base64 Decode:
MHhmdW57c3AwdDFmeV8=
→ 0xfun{sp0t1fy_
```

This revealed the initial portion of the flag.

---

## Step 3 — Playlist Metadata Analysis

In **Playlist 2**, the following song titles were listed:

- _WORLD  
- Maui Wowie  
- 0801  
- Riptide  
- 3 Strikes  
- _WORLD  
- Takedown  
- Rock That Body  
- 4 Raws  
- X Gon Give It To Ya  
- {}  

Extracting the **first character** from each title:

```
_M0R3_TR4X}
```

This formed the final segment of the flag.

---

## Final Flag Reconstruction

Combining all recovered parts:

- From Base64 decoding: `0xfun{sp0t1fy_`
- From Base58 decoding: `pl4yl1st_3xt3nd`
- From playlist title extraction: `_M0R3_TR4X}`

### ✅ Final Flag

```
0xfun{sp0t1fy_pl4yl1st_3xt3nd_M0R3_TR4X}
```

---

## Conclusion

This challenge required:

- Username enumeration
- Cross-platform OSINT pivoting (Reddit → Spotify)
- Base58 decoding
- Base64 decoding
- Metadata pattern analysis

The task demonstrates how seemingly harmless public information across platforms can be correlated to extract structured hidden data.
