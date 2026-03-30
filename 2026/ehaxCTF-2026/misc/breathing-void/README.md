CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)
Challenge Name: Breathing Void
Platform: ehaxCTF-2026
Category: Forensics
Difficulty: Medium
Time spent: 1 hour

1) Goal (What was the task?)
Analyze the provided PCAP file and recover the hidden flag matching the `EH4X{...}` format. Success meant extracting the covert message embedded in the non-Ethernet packet stream.

2) Key Clues (What mattered?)
- Prompt hinted at "dead vacuum" and finding "life," implying hidden data rather than overt traffic.
- File `Breathing_Void.pcap` contained 1.1 GB of merged captures with a tiny Raw IPv4 stream across interfaces 1 and 2.
- The 1-packet Raw IPv4 stream delivered a fake prompt-injection flag; the remaining 272 packets were uniform TCP ACKs with differing timings.
- Inter-packet delays were confined to two values (`0.01` vs `0.10` seconds), suggesting timing-based data.

3) Plan (Your first logical approach)
- Extract capture metadata (using `capinfos`, `tshark -z io,phs`) to identify small hidden streams within the massive PCAP.
- Filter for packets on interfaces 1 and 2 to isolate the covert timing channel and confirm that headers were constant.
- Translate inter-arrival times into bits and decode them as ASCII to reveal the real flag.

4) Steps (Clean execution)
1. Action: Ran `capinfos` and interface summaries to confirm the file merged `massive.pcap`, `decoy_trap.pcap`, and `covert_timing_2.pcap`. Result: noticed only 273 Raw IPv4 packets, pointing to a tiny embedded channel. Decision: focus on those packets.
2. Action: Filtered interface 2 packets with `tshark`, exporting arrival timestamps and headers. Result: all TCP/IPv4 headers were identical, signaling timing as the carrier. Decision: compute inter-packet delays.
3. Action: Calculated `0.01s` vs `0.10s` gaps from `if2_100k.tsv`, mapped them to bits and appended a leading zero. Result: ASCII conversion produced `EH4X{pc@p5_@re_of+en_mo5+1y_noi5e}`. Decision: flag captured.

5) Solution Summary (What worked and why?)
The covert channel hid the flag in timing rather than payload: uniform TCP ACKs carried no data, but their spacing alternated between `0.01s` (representing `0`) and `0.10s` (`1`). Converting those delays into a bitstream, padding with an extra leading zero, and interpreting the bytes as ASCII produced the real `EH4X{...}` flag.

6) Flag
```EH4X{pc@p5_@re_of+en_mo5+1y_noi5e}```

7) Lessons Learned (make it reusable)
- Timing differences can encode entire messages when headers/payloads stay constant; check inter-arrival stats whenever traffic looks uniform.
- Split large PCAPs by interface/time before deep analysis to isolate rare but important streams.
- Decode bitstreams with both endian offsets and leading padding when lengths seem off by a byte or two.

8) Personal Cheat Sheet (optional, but very useful)
- `capinfos Breathing_Void.pcap` → high-level metadata to spot merged/hidden captures.
- `tshark -r file -Y 'interface_id==X' -T fields -e frame.time_epoch` → extract timestamps for timing puzzles.
- Timing patterns → look for two distinct deltas and treat them as binary symbols when headers don’t change.
