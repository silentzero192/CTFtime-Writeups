# Regular Dude - Writeup

## Challenge

- **Name**: `regular-dude`
- **Category**: Web

## Flag

​	`RS{R3gul4r_Dud3_w1th_4n_1rregular_m0d37}`

## Summary

This challenge has two separate vulnerabilities that chain together cleanly:

1. The app trusts the `Username` HTTP header for admin authorization.
2. The admin-only model upload endpoint loads untrusted legacy Keras `.h5` files with `safe_mode=False`.

That gives us an unauthenticated path to arbitrary Python execution inside the Flask process, which we use to raise an exception containing the `FLAG` environment variable.

## Source Analysis

### 1. Admin access is controlled by a trusted header

In [`src/main.py`](src/main.py), the `admin_required` decorator does this:

```python
def admin_required(f):
    def wrapper(*args, **kwargs):
        username = session.get('username') or request.headers.get('Username', '')
        if re.match(r'^admin$', username, re.IGNORECASE):
            return f(*args, **kwargs)
        else:
            return jsonify({'error': 'Unauthorized'}), 401
```

This means:

- if there is no authenticated session,
- the application falls back to `request.headers["Username"]`,
- and if that header equals `admin` case-insensitively, the request is treated as admin.

So we do not need to register or log in at all. A request like this is enough to access admin-only routes:

```http
Username: admin
```

There is also a second auth bug nearby:

```python
elif username.lower() == 'admin':
    return jsonify({'error': 'Username "admin" is reserved'}), 400
```

That registration check can be bypassed with Unicode such as `admın` using a dotless `ı`, because `.lower()` and `re.IGNORECASE` do not behave identically. That bug is real, but it is not even necessary here because the header trust issue is simpler and fully unauthenticated.

### 2. The admin upload endpoint deserializes untrusted Keras models

Still in [`src/main.py`](src/main.py):

```python
@app.route('/model', methods=['POST'])
@admin_required
def model():
    ...
    model = keras.models.load_model(model_path, safe_mode=False)
    input_data = constant([[0.0]])
    predictions = model.predict(input_data)
```

This is the dangerous part:

- user-controlled `.h5` file,
- loaded with `keras.models.load_model(...)`,
- using the legacy HDF5 format,
- with `safe_mode=False`.

Legacy Keras `.h5` models can contain serialized Python `Lambda` layer bytecode. When the model is loaded, that code is deserialized and later executed when the layer is built or run.

The Dockerfile also tells us exactly where the flag lives:

```dockerfile
ENV FLAG=REDACTED
```

So the intended target is almost certainly `os.environ["FLAG"]`.

## Exploit Strategy

We upload a malicious legacy `.h5` model containing a `Lambda` layer whose body is effectively:

```python
lambda x: exec('import os\nraise Exception(os.environ["FLAG"])')
```

When Keras loads or runs that layer, it raises an exception containing the flag. The Flask handler catches that exception and returns it directly in JSON:

```python
except Exception as e:
    return jsonify({'error': str(e)}), 500
```

That turns code execution into an easy flag leak.

## Manual Exploit Flow

1. Send a request to `/model` with header `Username: admin`.
2. Upload a malicious legacy Keras `.h5` file.
3. Let the `Lambda` layer raise an exception with `os.environ["FLAG"]`.
4. Read the flag from the JSON error response.

## Solver Script

The included [`solve.py`](solve.py) does exactly that:

- builds a minimal malicious HDF5 Keras model,
- sends it to the live challenge with `Username: admin`,
- extracts and prints the `RS{...}` flag from the response.

Usage:

```bash
python3 solve.py https://regular-dude-fd368def-8f76-4013-a0a4-6d9f5e672141.ctf.ritsec.club/
```

## Why the Payload Uses a Precomputed Marshaled Blob

Keras stores Python lambda bytecode in legacy `.h5` files using Python's `marshal` format. The target server runs:

- Python `3.10.20`

Marshal output is version-sensitive, so the bytecode blob in `solve.py` was generated with Python 3.10 to match the target runtime.

## Real Response

The live instance returned the flag inside the JSON error body:

```json
{
  "error": "Exception encountered when calling Lambda.call().\n\n\"RS{R3gul4r_Dud3_w1th_4n_1rregular_m0d37}\"\n\nArguments received by Lambda.call(): ..."
}
```

## Lessons Learned

- Never trust authentication state from arbitrary request headers unless a trusted upstream proxy injects them and direct access is impossible.
- Never load untrusted Keras or TensorFlow model files.
- `safe_mode=False` on attacker-controlled model artifacts is equivalent to arbitrary code execution.
- Returning raw exception text to users turns code execution into easy data exfiltration.
