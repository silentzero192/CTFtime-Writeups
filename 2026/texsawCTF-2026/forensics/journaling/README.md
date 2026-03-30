# journaling Writeup

Challenge Name: journaling  
Platform: texsawCTF 2026  
Category: Forensics  
Difficulty: Medium  
Time spent: about 1 hour

## 1) Goal (What was the task?)
The challenge described a Windows machine used for journaling and note-taking that may have been infected by malware. The objective was to examine the disk evidence, recover any useful traces left behind, and rebuild the final flag from multiple segments.

Success meant finding every flag segment, proving the correct order, and combining them with underscores in the format `texsaw{part1_part2_part3}`.

## 2) Key Clues (What mattered?)
- The challenge name was `journaling`, which strongly suggested NTFS journal artifacts might matter.
- The description mentioned malware evidence left on disk, so deleted/renamed files and metadata were immediately relevant.
- Note 1 said enough information was present to determine the order of the segments.
- Note 2 said the flag segments had to be joined with underscores.
- The extracted evidence file was `evidence.001`.
- The user note later mentioned: `find out where part 5 is...`, which pointed toward a hidden or non-obvious storage location.
- The image turned out to be an NTFS volume, so NTFS-specific artifacts like `$UsnJrnl`, `$LogFile`, ADS, and deleted MFT entries became the focus.

## 3) Plan (Your first logical approach)
- First, identify what kind of evidence `evidence.001` actually is and whether it contains partitions.
- Next, enumerate the filesystem to find the user profile, notes, and anything obviously suspicious.
- After that, inspect user-created files and any alternate data streams because note-taking challenges often hide data there.
- Finally, pivot into NTFS metadata and deleted-file artifacts to recover anything that no longer exists as a normal visible file.

## 4) Steps (Clean execution)

### 1. Identify the evidence format
Action:
- Ran:

```bash
file evidence.001
fdisk -l evidence.001
mmls evidence.001
```

Result:
- `evidence.001` was a raw 1 GiB disk image with an MBR partition table.
- There was one NTFS partition.
- The partition started at sector `128`.

Decision:
- All Sleuth Kit commands needed to use the NTFS partition offset `-o 128`.

### 2. Enumerate the filesystem
Action:
- Ran:

```bash
fls -o 128 evidence.001
fls -o 128 evidence.001 -r -p
fsstat -o 128 evidence.001
```

Result:
- The root contained the expected Windows directories and one user profile: `Users/user`.
- Important paths appeared quickly:
  - `Users/user/Notes/tasks.txt`
  - `Users/user/Notes/tasks.txt:source`
  - NTFS metadata like `$UsnJrnl` and `$LogFile`
- The Recycle Bin also contained a lot of deleted files, so deleted artifacts were definitely in play.

Decision:
- Start with the user note because it was the most likely place to hide instructions or a first flag piece.

### 3. Inspect the note and its alternate data stream
Action:
- Ran:

```bash
istat -o 128 evidence.001 945
icat -o 128 evidence.001 945-128-1 | iconv -f utf-16le -t utf-8
icat -o 128 evidence.001 945-128-3
```

Result:
- `tasks.txt` contained:

```text
To Do: Image infected device and analyze in Autopsy, identify IoCs, create timeline of events, find out where part 5 is...
```

- The alternate data stream `tasks.txt:source` contained:

```text
flagsegment_3fd19982505363d0
```

Important meaning:
- This immediately gave one flag segment: `3fd19982505363d0`.
- The phrase `find out where part 5 is...` told me one segment was intentionally hidden somewhere non-obvious.

Decision:
- Because the challenge is called `journaling`, the next place to check was NTFS journaling metadata rather than only normal files.

### 4. Query the USN journal
Action:
- Ran:

```bash
usnjls -o 128 evidence.001
usnjls -o 128 evidence.001 | rg "flagsegment_|tasks.txt|Notes|RENAME_|FILE_DELETE|STREAM_CHANGE|NAMED_DATA"
```

Result:
- The USN journal showed a very useful sequence of file activity:

```text
FILE_CREATE  flagsegment_u5njOurn@l
FILE_CREATE  Notes
FILE_CREATE  flagsegment_unc0v3rs.txt
RENAME_OLD_NAME  flagsegment_unc0v3rs.txt
RENAME_NEW_NAME  notetoself.txt
FILE_CREATE  monitor.log
FILE_CREATE  flagsegment_f1les.txt
FILE_DELETE CLOSE  flagsegment_f1les.txt
FILE_CREATE  tasks.txt
STREAM_CHANGE / NAMED_DATA_EXTEND  tasks.txt
```

This was the first major breakthrough because it revealed three more flag-like strings:
- `u5njOurn@l`
- `unc0v3rs`
- `f1les`

Decision:
- Recover the related MFT entries to confirm whether those segments were stored as names, contents, or both.

### 5. Inspect the files and directory referenced by the journal
Action:
- Enumerated the suspicious directory:

```bash
fls -o 128 evidence.001 940
```

- Then inspected the related entries:

```bash
istat -o 128 evidence.001 940
istat -o 128 evidence.001 942
istat -o 128 evidence.001 943
istat -o 128 evidence.001 944

icat -o 128 evidence.001 942
icat -o 128 evidence.001 943
icat -o 128 evidence.001 944
```

Result:
- Entry `940` was a directory named:

```text
flagsegment_u5njOurn@l
```

- That directory contained:
  - `notetoself.txt`
  - `monitor.log`
  - deleted `flagsegment_f1les.txt`

- `notetoself.txt` was originally created as `flagsegment_unc0v3rs.txt`, then renamed.
- `flagsegment_f1les.txt` still existed as a deleted MFT entry and its content was:

```text
Must be deleted
```

- `notetoself.txt` contained:

```text
Super important stolen data: username: user password: password
```

What mattered:
- The contents of these files were mostly decoys.
- The useful data was in the file and directory names themselves.

Recovered segments so far:
- `u5njOurn@l`
- `unc0v3rs`
- `f1les`
- `3fd19982505363d0`

Decision:
- `monitor.log` was now empty, but the USN journal showed it had been created, written, and then truncated.
- That made it the perfect candidate for a hidden segment that only survived in the NTFS transaction log.

### 6. Mine `$LogFile` for wiped data
Action:
- Searched the NTFS transaction log directly:

```bash
icat -o 128 evidence.001 2-128-1 | strings -a -el | rg "flagsegment_|monitor.log|notetoself|tasks.txt"
```

- After finding a new candidate string, I pulled raw context around it:

```bash
icat -o 128 evidence.001 2-128-1 > /tmp/logfile.bin
xxd -s 79940 -l 220 /tmp/logfile.bin
```

Result:
- `$LogFile` contained a string that did not appear in any normal directory listing:

```text
flagsegment_4lter3d
```

- The raw UTF-16 bytes showed it was a real stored string in the transaction log, not just random noise:

```text
fffe 6600 6c00 6100 6700 7300 6500 6700 6d00 6500 6e00 7400 5f00 3400 6c00 7400 6500 7200 3300 6400
```

That decodes to:

```text
flagsegment_4lter3d
```

Why this mattered:
- `monitor.log` had been created and then truncated.
- The visible file was empty.
- The segment survived only inside `$LogFile`, which fits the challenge theme perfectly: journal artifacts reveal what regular file views no longer show.

Decision:
- At this point I had all five parts:
  - `u5njOurn@l`
  - `unc0v3rs`
  - `4lter3d`
  - `f1les`
  - `3fd19982505363d0`
- The last task was to prove the order.

### 7. Reconstruct the correct order
Action:
- Used the USN and MFT timestamps around entries `940` to `945`.

Key times:
- `2026-01-24 05:25:02 PKT` -> `flagsegment_u5njOurn@l`
- `2026-01-24 05:25:05 PKT` -> `flagsegment_unc0v3rs.txt`
- `2026-01-24 05:25:10 PKT` -> `monitor.log` activity; `$LogFile` preserved `flagsegment_4lter3d`
- `2026-01-24 05:25:15 PKT` -> `flagsegment_f1les.txt`
- `2026-01-24 05:25:20 PKT` -> `tasks.txt:source` containing `3fd19982505363d0`

Result:
- The order was chronological.
- It also formed a coherent phrase:

```text
u5njOurn@l unc0v3rs 4lter3d f1les
```

- The ADS hex segment clearly came last because the note explicitly hinted to “find out where part 5 is,” and it was written after the earlier journal activity.

## 5) Solution Summary (What worked and why?)
The challenge was solved by treating NTFS metadata as primary evidence instead of only looking at normal user files. One segment was stored in an alternate data stream, three segments were hidden in directory and file names recovered from the USN journal, and the final missing segment survived only inside `$LogFile` after a visible file was truncated. The challenge name `journaling` was the core hint: the NTFS journals preserved the story of what was created, renamed, deleted, and partially wiped.

## 6) Flag
`texsaw{u5njOurn@l_unc0v3rs_4lter3d_f1les_3fd19982505363d0}`

## 7) Lessons Learned (make it reusable)
- In Windows forensics, do not stop at live files. NTFS metadata can preserve evidence that the visible filesystem no longer shows.
- If a challenge mentions ordering, build a timeline instead of guessing the most readable phrase.
- Always check alternate data streams on NTFS files because they are common hiding spots in both malware and CTFs.
- If a file was created and truncated, inspect `$LogFile` and `$UsnJrnl` because the interesting content may still survive there.

## 8) Personal Cheat Sheet (optional, but very useful)
- `file evidence.001` -> identify whether the evidence is a raw disk, archive, or something else.
- `fdisk -l evidence.001` -> quickly confirm partitions and sizes.
- `mmls evidence.001` -> find the exact partition offset for Sleuth Kit work.
- `fls -o 128 evidence.001 -r -p` -> recursively list files with full paths from the NTFS partition.
- `istat -o 128 evidence.001 <inode>` -> inspect timestamps, attributes, and ADS information for an MFT entry.
- `icat -o 128 evidence.001 <inode>` -> recover the content of a file directly from the image.
- `icat -o 128 evidence.001 <inode>-128-3` -> extract a named data stream when `istat` shows an ADS exists.
- `usnjls -o 128 evidence.001` -> inspect the NTFS USN journal for create/rename/delete history.
- `icat -o 128 evidence.001 2-128-1 | strings -a -el` -> search `$LogFile` for UTF-16 strings.
- `strings -a -el` -> essential when Windows artifacts are stored in UTF-16.
- Pattern to remember: `empty file + journal activity + weird timestamps` often means the real evidence was wiped from the live file but still exists in NTFS metadata.
