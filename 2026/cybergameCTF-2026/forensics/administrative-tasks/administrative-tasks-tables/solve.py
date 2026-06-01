#!/usr/bin/env python3
import re
import zipfile
import xml.etree.ElementTree as ET

XL_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
MSG_PATTERN = re.compile(r"HIDDEN_MSG_([1-4])_\{[^}]+\}")
RESULTZ_REF = re.compile(r"Resultz!([A-Z]+[0-9]+)")


def gather_hidden_messages(zf):
    found = {}
    for name in zf.namelist():
        if not name.endswith(".xml"):
            continue
        raw = zf.read(name)
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            continue
        text_parts = []
        for elem in root.iter():
            tag = elem.tag
            if isinstance(tag, str) and (tag.endswith("}t") or tag == "t"):
                text_parts.append(elem.text or "")
        text = "".join(text_parts)
        for match in MSG_PATTERN.finditer(text):
            index = int(match.group(1))
            found.setdefault(index, match.group(0))
    return found


def build_value_map(zf):
    tree = ET.fromstring(zf.read("xl/worksheets/sheet5.xml"))
    values = {}
    for cell in tree.findall(f".//{XL_NS}c"):
        ref = cell.get("r")
        if not ref:
            continue
        if cell.get("t") == "s":
            continue
        v = cell.find(f"{XL_NS}v")
        if v is None or v.text is None:
            continue
        try:
            values[ref] = float(v.text)
        except ValueError:
            try:
                values[ref] = float(v.text.replace(",", ""))
            except ValueError:
                continue
    return values


def extract_chars_from_formula(formula):
    chars = []
    idx = 0
    while True:
        idx = formula.find("CHAR(", idx)
        if idx == -1:
            break
        start = idx + 5
        depth = 1
        j = start
        while j < len(formula) and depth > 0:
            ch = formula[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            j += 1
        chars.append(formula[start : j - 1])
        idx = j
    return chars


def evaluate_expression(expr, value_map):
    def repl(match):
        key = match.group(1)
        if key not in value_map:
            raise ValueError(f"missing Resultz cell {key}")
        return f"value_map['{key}']"

    expr_py = RESULTZ_REF.sub(repl, expr).replace("ROUND", "round")
    return eval(expr_py, {"__builtins__": None}, {"round": round, "value_map": value_map})


def extract_message3(zf):
    value_map = build_value_map(zf)
    tree = ET.fromstring(zf.read("xl/worksheets/sheet6.xml"))
    lines = []
    for row in tree.findall(f".//{XL_NS}row"):
        row_chars = []
        for cell in row.findall(f"{XL_NS}c"):
            formula = cell.find(f"{XL_NS}f")
            if formula is None or formula.text is None:
                continue
            for inner in extract_chars_from_formula(formula.text):
                value = evaluate_expression(inner, value_map)
                row_chars.append(chr(int(round(value))))
        if row_chars:
            lines.append("".join(row_chars))
    script_text = "\n".join(lines)
    assignments = re.findall(r'a\s*=\s*"([^"]+)"', script_text)
    if len(assignments) < 2:
        raise ValueError("unable to parse string constants inside sheet6")
    tail = next((x for x in assignments if "_3_GSM_" in x), None)
    head = next((x for x in assignments if "_3_GSM_" not in x), None)
    if not head or not tail:
        raise ValueError("expected two assignments for part 3")
    head_text = head[::-1]
    if head_text.startswith("G"):
        head_text = "H" + head_text[1:]
    tail_text = tail[::-1]
    return head_text + tail_text


def extract_message4(zf):
    data = zf.read("xl/persons/person.xml").decode("utf-8")
    match = re.search(r"HIDDEN_MSG_4_\{[^}]+\}", data)
    if not match:
        raise ValueError("part 4 string missing in persons metadata")
    return match.group(0)


def flag_from_zip(password):
    with zipfile.ZipFile("flag1.zip") as zf:
        data = zf.read("flag1.txt", pwd=password.encode())
    return data.decode("utf-8").strip()


def main():
    with zipfile.ZipFile("Excel.xlsm") as workbook:
        messages = gather_hidden_messages(workbook)
        messages.setdefault(3, extract_message3(workbook))
        messages.setdefault(4, extract_message4(workbook))

    for idx in range(1, 5):
        if idx not in messages:
            raise SystemExit(f"part {idx} missing")

    order = [1, 4, 2, 3]
    password = "".join(messages[idx].split("{", 1)[1].rstrip("}") for idx in order)
    flag = flag_from_zip(password)

    print("Hidden parts:")
    for idx in range(1, 5):
        print(f"  part {idx}: {messages[idx]}")
    print("FLAG_PASSWORD =", password)
    print("Flag:", flag)


if __name__ == "__main__":
    main()
