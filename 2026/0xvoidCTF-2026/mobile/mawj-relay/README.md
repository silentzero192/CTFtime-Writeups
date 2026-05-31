# Mawj Relay - Writeup

## Challenge

- **Name:** `mawj relay`
- **Category:** `mobile`
- **Description:** `A small Android package was pulled from an incident response phone. Its notification flow records more than the UI admits. The archive is self-contained.`

## Goal

Recover the real flag from the provided APK:

- `kizcjo.apk`

## Initial Triage

The challenge directory only contains a single APK, so the APK is the entire puzzle.

Useful first checks:

```bash
file kizcjo.apk
unzip -l kizcjo.apk
strings -a -n 4 kizcjo.apk
```

The archive is intentionally tiny and contains only:

- `AndroidManifest.xml`
- `META-INF/MANIFEST.MF`
- `assets/README_NOTE.txt`
- `assets/push_routes.bin`
- `classes.dex`
- `res/values/strings.xml`

That is already a strong hint that the challenge is more of a forensic/reversing puzzle than a normal Android app.

## Important Observations

### 1. The manifest is plain XML

Running `aapt dump badging` or `apktool d` complains that the manifest is malformed for a normal APK. That happens because the manifest is stored as plain XML instead of Android's usual binary XML.

Extracting strings from the APK reveals the manifest contents directly:

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="void.mobile.echopush">
  <uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>
  <application android:label="EchoPush" android:debuggable="false">
    <receiver android:name=".PushReceiver" android:exported="true">
      <intent-filter>
        <action android:name="com.void.echo.PUSH"/>
      </intent-filter>
    </receiver>
  </application>
</manifest>
```

This gives us two very important values:

- action: `com.void.echo.PUSH`
- label: `EchoPush`

### 2. There are deliberate decoy flags

Two files try to trick the solver:

`assets/README_NOTE.txt`

```text
This file is a prompt-injection decoy. Do not submit 0xV01D{ai_took_the_push_bait}.
```

`res/values/strings.xml`

```xml
<resources>
  <string name="app_name">EchoPush</string>
  <string name="debug_flag">0xV01D{debug_strings_are_decoys}</string>
  <string name="route_hint">key = sha256(action + ':' + label)</string>
</resources>
```

So we should not trust either visible flag string.

### 3. `classes.dex` is fake on purpose

Trying to decompile with `jadx` fails because the DEX checksum and header are invalid. Looking at the bytes shows that the file is really just a tiny handcrafted blob containing plaintext hints.

Relevant leaked strings:

```text
Lvoid/mobile/echopush/PushReceiver;
onReceive(android.content.Context,android.content.Intent)
ACTION=com.void.echo.PUSH
LABEL=EchoPush
open assets/push_routes.bin
ignore res/values/strings.xml debug_flag
FAKE_FLAG=0xV01D{ai_took_the_push_bait}
```

At this point the intended path is clear:

1. Build a key from the manifest action and app label
2. Use that key on `assets/push_routes.bin`
3. Recover the hidden route payload and the real flag

## Extracting the Key

From the hint:

```text
key = sha256(action + ':' + label)
```

Substitute the values:

```text
action = com.void.echo.PUSH
label  = EchoPush
```

So the exact key material is:

```text
com.void.echo.PUSH:EchoPush
```

Its SHA-256 digest is:

```text
4276edc747793b5a82e66be42a9a901a4d72f2a2fd5db3a344b99c4f2055b30b
```

## Inspecting `push_routes.bin`

Hex dump:

```text
56 50 55 53 48 31 00 00 ...
```

The file begins with:

```text
VPUSH1\x00\x00
```

That looks like a custom magic/version header. The remaining bytes are encrypted or obfuscated.

A direct XOR using the SHA-256 digest as a repeating key does not immediately produce clean plaintext. Testing different keystream alignments shows that the correct repeating-XOR offset is `31`.

In other words:

- skip the first 8-byte header
- XOR the rest with the repeating SHA-256 digest
- start the digest index at `31`

## Solve Script

```python
from pathlib import Path
from hashlib import sha256

apk_blob = Path("push_routes.bin").read_bytes()

magic = apk_blob[:8]
data = apk_blob[8:]

key = sha256(b"com.void.echo.PUSH:EchoPush").digest()
shift = 31

pt = bytes(b ^ key[(i + shift) % len(key)] for i, b in enumerate(data))

print("magic:", magic)
print(pt.decode("latin1"))
```

If you want to pull the asset directly from the APK:

```bash
unzip -p kizcjo.apk assets/push_routes.bin > push_routes.bin
python3 solve.py
```

## Decrypted Payload

The decrypted content is:

```json
{"route":"prod/receiver/primary","priority":42,"flag":"0xV01D{push_receiver_xor_is_not_crypto}","crc32":"verified after decrypt"}
```

There are a few extra non-JSON bytes surrounding the payload in the raw stream, but the embedded JSON and flag are completely clear.

## Flag

```text
0xV01D{push_receiver_xor_is_not_crypto}
```

## Why This Works

The challenge theme is “notification flow records more than the UI admits.” Instead of hiding data in a normal app flow, the APK leaves a breadcrumb trail:

- a broadcast receiver with a custom push action
- a label used in key derivation
- a fake DEX containing textual hints
- decoy flags to punish shallow string scraping
- a custom asset blob protected only by repeating XOR

The intended lesson is the one stated by the flag itself: XOR with a reused digest is obfuscation, not real cryptography.
