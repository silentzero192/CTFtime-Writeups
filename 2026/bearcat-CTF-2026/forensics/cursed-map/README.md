# CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)

**Challenge Name:** Cursed Map  
**Platform:** Bearcat CTF 2026  
**Category:** Forensics  
**Difficulty:** Medium  
**Time spent:** ~45 minutes

## 1) Goal (What was the task?)
The challenge gave one artifact, `map.pcap`, and hinted that opening the map kills people.  
Success condition was to recover a flag in the format `BCCTF{...}` from that packet capture.

## 2) Key Clues (What mattered?)
- Only one file was provided: `map.pcap`.
- Network traffic showed a request for `GET /flag.txt HTTP/1.1`.
- HTTP response headers included `Content-Encoding: br` (Brotli) and a large body.
- The decompressed output behaved like a Brotli bomb (very large repetitive output).
- The compressed body had a strong repeating structure (period ~105 bytes), which suggested hidden nested data.

## 3) Plan (Your first logical approach)
- Inspect the pcap first to identify the protocol and transferred object.
- Reassemble the HTTP response body from TCP segments.
- Decode Brotli safely (streaming / capped output) to avoid memory blowups.
- If direct decode is toxic, probe for nested Brotli streams at structured offsets and scan for `BCCTF{...}`.

## 4) Steps (Clean execution)
1. **Action:** Listed files and checked capture metadata.  
   **Result:** Found a single pcap with one HTTP conversation.  
   **Decision:** Focus entirely on extracting HTTP payload.

2. **Action:** Read packet text with `tcpdump` and `strings`.  
   **Result:** Confirmed `GET /flag.txt` and response header `Content-Encoding: br`.  
   **Decision:** Reconstruct HTTP response body exactly.

3. **Action:** Parsed the pcap and reassembled server-to-client TCP payload into one stream, then split headers/body.  
   **Result:** Recovered `http_response_body.br` (860207 bytes).  
   **Decision:** Attempt Brotli decompression.

4. **Action:** Tried direct Brotli decode.  
   **Result:** Output exploded to multi-GB repetitive data (Brotli bomb behavior), no immediate flag.  
   **Decision:** Analyze compressed bytes for pattern/offset tricks.

5. **Action:** Measured periodicity of the compressed body.  
   **Result:** Strong repeat period at 105 bytes; mostly a few repeated 105-byte block types.  
   **Decision:** Probe Brotli decoding from offsets aligned to that period.

6. **Action:** Tested Brotli decompression from offsets in `105`-byte steps using a small max output cap, then streamed candidate offsets.  
   **Result:** Offset `174720` started a valid nested Brotli stream containing the flag immediately.  
   **Decision:** Automate all logic in one script.

7. **Action:** Wrote `solve.js` to parse pcap, extract the Brotli body, detect candidate nested stream offsets, and print the flag.  
   **Result:** Running `node solve.js map.pcap` prints the final flag.

## 5) Solution Summary (What worked and why?)
The main trap was that the HTTP body was Brotli-compressed but intentionally bomb-like when decoded from byte 0.  
The real payload was hidden as a second valid Brotli stream starting at an internal offset (`174720`).  
By reassembling traffic correctly, then scanning structured offsets in the compressed data instead of blindly decompressing everything, the script quickly found and extracted the real flag.

## 6) Flag
`BCCTF{00H_1M_bR07l1_f33ls_S0_g0Od!}`

## 7) Lessons Learned (make it reusable)
- In forensics pcaps, always inspect HTTP headers first; compression metadata is often critical.
- If decompression output is absurdly huge/repetitive, suspect bombs or nested/offset-embedded streams.
- Build capped/streaming decode workflows instead of full-memory decompression.
- Repetition/periodicity analysis on compressed blobs can reveal structure and carving offsets.

## 8) Personal Cheat Sheet (optional, but very useful)
- `tcpdump -nn -r map.pcap -c 40` -> quick protocol/flow overview.
- `strings -n 6 map.pcap | head` -> quick plaintext clues from capture.
- Reassemble TCP payload by `seq` -> required before reliable HTTP body extraction.
- `Content-Encoding: br` -> decode with Brotli (Node `zlib` works well).
- Brotli bomb symptom -> use streaming scan + output cap, not full decompression.
- Offset carving pattern -> test decode at periodic boundaries when data is repetitive.
