# Stipend Validator — Writeup

**Challenge**: Stipend Validator  
**Category**: Reverse Engineering / Web  
**Flag**: `SDG{fd5f456cbdfc275f4661bead4e44d983}`

---

## Overview

The redemption check for this challenge runs entirely in the browser. The challenge presents a client-side JavaScript bundle that has been run through an obfuscator, but the validator's two state arrays remain as plain literals. The validation is a simple char-by-char XOR against a repeating short key. Recovering the stipend code lets us POST it to the server and obtain a redemption token, which is then used to claim the flag.

```
Challenge URL:
https://hackforachangeruntime.vercel.app/r/7fa3677f-83a7-4511-8873-3a3b1db41d01/stipend-validator?token=eyJ...
```

```
API endpoint:
https://hackforachangeruntime.vercel.app/api/stipend-validator?seed=14a5766d3b669c1c7d1ab2680d42ccb92a50fa1a727216ed4fb4194359619c7b
```

---

## Step 1 — Fetch the Obfuscated JS Bundle

The challenge UI has a "Load bundle" button that hits the API with `action=app`. We can do the same via curl:

```bash
curl "https://hackforachangeruntime.vercel.app/api/stipend-validator?seed=14a5766d3b669c1c7d1ab2680d42ccb92a50fa1a727216ed4fb4194359619c7b&action=app"
```

Response:

```json
{
  "ok": true,
  "bundle_js": ";(function(){\n  var _0xa12b=[\"Enter stipend code\",\"Validating…\",\"Invalid code.\",\"STUDENT STIPEND PORTAL v1.4\",\"Code accepted.\"];\n  function _0x1d(_0x2e){return _0xa12b[_0x2e];}\n  var _0xff=[0x25,0x70,0x94,0x05,0x9d,0xa6,0xea,0xdd,0x74,0x70,0x9c,0x54,0xcf,0xf5,0xe8,0xda,0x22,0x72,0x99,0x02,0xcb,0xf1,0xed,0x8c];\n  var _0x77=[0x11,0x40,0xad,0x64,0xfc,0xc4,0xdd,0xb8];\n  var _0x4c=function(_0x9){\n    var _0x5=_0x9.length;\n    if(_0x5!==_0xff.length)return ![];\n    var _0x6=0x0;\n    for(;_0x6<_0x5;_0x6++){\n      var _0x7=_0x9.charCodeAt(_0x6);\n      var _0x8=_0x77[_0x6%_0x77.length];\n      if((_0x7^_0x8)!==_0xff[_0x6])return ![];\n    }\n    return !![];\n  };\n  (window.__stipend=window.__stipend||{}).validate=_0x4c;\n  (window.__stipend.banner=function(){return _0x1d(0x3);});\n})();",
  "baked_length": 24,
  "instructions": "Run the bundle, then call window.__stipend.validate(\"<code>\"). True means the code matches."
}
```

---

## Step 2 — Identify the Two State Arrays

The hints told us exactly what to look for: *"Two array literals carry the validator state. Find them in the bundle and you have everything."*

In the bundle, these two arrays are immediately visible despite the obfuscation:

### Expected values (`_0xff`) — 24 bytes

```javascript
var _0xff = [
  0x25, 0x70, 0x94, 0x05, 0x9d, 0xa6, 0xea, 0xdd,
  0x74, 0x70, 0x9c, 0x54, 0xcf, 0xf5, 0xe8, 0xda,
  0x22, 0x72, 0x99, 0x02, 0xcb, 0xf1, 0xed, 0x8c
];
```

### XOR key (`_0x77`) — 8 bytes

```javascript
var _0x77 = [0x11, 0x40, 0xad, 0x64, 0xfc, 0xc4, 0xdd, 0xb8];
```

---

## Step 3 — Reverse the Validation Logic

The validator function `_0x4c` (exposed as `window.__stipend.validate`) does:

```javascript
function validate(code) {
    if (code.length !== 24) return false;
    for (var i = 0; i < 24; i++) {
        var charCode = code.charCodeAt(i);
        var keyByte = key[i % key.length];           // _0x77[i % 8]
        if ((charCode ^ keyByte) !== expected[i])     // _0xff[i]
            return false;
    }
    return true;
}
```

The check is: `code[i] ^ key[i % 8] == expected[i]`

Since XOR is its own inverse, the correct code is:

```
code[i] = expected[i] ^ key[i % 8]
```

Computing this for all 24 positions:

```python
expected = [
    0x25, 0x70, 0x94, 0x05, 0x9d, 0xa6, 0xea, 0xdd,
    0x74, 0x70, 0x9c, 0x54, 0xcf, 0xf5, 0xe8, 0xda,
    0x22, 0x72, 0x99, 0x02, 0xcb, 0xf1, 0xed, 0x8c
]
key = [0x11, 0x40, 0xad, 0x64, 0xfc, 0xc4, 0xdd, 0xb8]

code = ''.join(chr(expected[i] ^ key[i % 8]) for i in range(24))
print(code)  # 409aab7ee010315b324f7504
```

| i | expected[i] | key[i % 8] | XOR result | Char |
|---|---|---|---|---|
| 0 | 0x25 | 0x11 | 0x34 | `4` |
| 1 | 0x70 | 0x40 | 0x30 | `0` |
| 2 | 0x94 | 0xad | 0x39 | `9` |
| 3 | 0x05 | 0x64 | 0x61 | `a` |
| 4 | 0x9d | 0xfc | 0x61 | `a` |
| 5 | 0xa6 | 0xc4 | 0x62 | `b` |
| 6 | 0xea | 0xdd | 0x37 | `7` |
| 7 | 0xdd | 0xb8 | 0x65 | `e` |
| 8 | 0x74 | 0x11 | 0x65 | `e` |
| 9 | 0x70 | 0x40 | 0x30 | `0` |
| 10 | 0x9c | 0xad | 0x31 | `1` |
| 11 | 0x54 | 0x64 | 0x30 | `0` |
| 12 | 0xcf | 0xfc | 0x33 | `3` |
| 13 | 0xf5 | 0xc4 | 0x31 | `1` |
| 14 | 0xe8 | 0xdd | 0x35 | `5` |
| 15 | 0xda | 0xb8 | 0x62 | `b` |
| 16 | 0x22 | 0x11 | 0x33 | `3` |
| 17 | 0x72 | 0x40 | 0x32 | `2` |
| 18 | 0x99 | 0xad | 0x34 | `4` |
| 19 | 0x02 | 0x64 | 0x66 | `f` |
| 20 | 0xcb | 0xfc | 0x37 | `7` |
| 21 | 0xf1 | 0xc4 | 0x35 | `5` |
| 22 | 0xed | 0xdd | 0x30 | `0` |
| 23 | 0x8c | 0xb8 | 0x34 | `4` |

**Stipend code: `409aab7ee010315b324f7504`**

---

## Step 4 — Submit the Code to the Server

The challenge UI has a "POST /submit" button that sends the code to the API with `action=submit`. We do the same:

```bash
curl -X POST "https://hackforachangeruntime.vercel.app/api/stipend-validator?seed=14a5766d3b669c1c7d1ab2680d42ccb92a50fa1a727216ed4fb4194359619c7b&action=submit" \
  -H "Content-Type: application/json" \
  -d '{"code":"409aab7ee010315b324f7504"}'
```

Response:

```json
{
  "ok": true,
  "message": "Stipend redemption confirmed.",
  "redemption_token": "989ff01275c4f69d173c4b86d218d91c",
  "note": "Submit redemption_token to claim-runtime-flag as proof."
}
```

The server accepted our code and returned a 32-hex-char **redemption token**: `989ff01275c4f69d173c4b86d218d91c`.

---

## Step 5 — Claim the Flag

The runtime JS reveals the claim endpoint:

```
POST https://vgwukffsjudbybdeuodn.supabase.co/functions/v1/claim-runtime-flag
Content-Type: application/json
Authorization: Bearer <launch_token>

{ "token": "<launch_token>", "proof": "<redemption_token>", "slug": "stipend-validator" }
```

Submitting gives the flag:

```
SDG{fd5f456cbdfc275f4661bead4e44d983}
```

---

## Summary

| Step | What | Result |
|---|---|---|
| 1 | Fetch the JS bundle from `/api/stipend-validator?action=app` | Obfuscated bundle with plain array literals |
| 2 | Extract the two arrays: `_0xff` (24 expected bytes) and `_0x77` (8-byte XOR key) | `_0xff = [...]`, `_0x77 = [...]` |
| 3 | Reverse the XOR: `code[i] = expected[i] ^ key[i % 8]` | `409aab7ee010315b324f7504` |
| 4 | POST code to `/api/stipend-validator?action=submit` | `redemption_token = "989ff01275c4f..."` |
| 5 | Submit redemption token to `claim-runtime-flag` | `SDG{fd5f456cbdfc275f4661bead4e44d983}` |

The entire challenge is a lesson in client-side security: obfuscation does not protect secrets. The two state arrays were left as plain literals, and the XOR operation is trivially reversible. The stipend code was never secret — it was derived entirely from constants embedded in the client-side code.
