import random
import string
import json
from datetime import datetime
from pathlib import Path

def multiply(v1, v2):
    return v1 * v2

# ---------- special fuzz objects ----------
class ValueErrorMul:
    def __mul__(self, other):
        raise ValueError("mul failed on purpose")

    def __repr__(self):
        return "ValueErrorMul()"

class ZeroDivMul:
    def __mul__(self, other):
        raise ZeroDivisionError("simulated divide by zero inside __mul__")

    def __repr__(self):
        return "ZeroDivMul()"

class RuntimeMul:
    def __mul__(self, other):
        raise RuntimeError("runtime boom from __mul__")

    def __repr__(self):
        return "RuntimeMul()"


def simpleFuzzer():
    max_errors = 10
    errors_collected = []
    seen_signatures = set()

    naughty_strings = load_naughty_strings("blns.json")

    total_tests = 2000

    for _ in range(total_tests):
        call_kind = random.randint(0, 8)

        v1 = make_random_value(naughty_strings)
        v2 = make_random_value(naughty_strings)
        v3 = make_random_value(naughty_strings)

        try:
            # --- different call styles to mix errors ---
            if call_kind == 0:
                multiply(v1, v2)  # normal
            elif call_kind == 1:
                multiply(v1)  # missing arg
            elif call_kind == 2:
                multiply(v1, v2, v3)  # too many
            elif call_kind == 3:
                # unexpected kw
                multiply(v1, badkw=v2)
            elif call_kind == 4:
                # try to force huge repeat -> possible MemoryError
                huge = 10_000_000_000  # large number
                multiply([1], huge)
            else:
                multiply(v1, v2)
        except Exception as e:
            sig = f"{type(e).__name__}:{str(e)}"
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                errors_collected.append({
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                    "inputs": {
                        "v1": repr(v1),
                        "v2": repr(v2),
                        "v3": repr(v3),
                        "call_kind": call_kind,
                    },
                    "error_type": type(e).__name__,
                    "error_msg": str(e),
                })
                if len(errors_collected) >= max_errors:
                    break

    with open("collected_errors_2.txt", "w", encoding="utf-8") as f:
        for err in errors_collected:
            f.write(json.dumps(err, ensure_ascii=False) + "\n")

    print(f"Fuzzing done. Collected {len(errors_collected)} errors in collected_errors_2.txt")


def load_naughty_strings(filename: str):
    path = Path(filename)
    if path.exists():
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
        except Exception as e:
            print(f"[!] Could not load {filename}: {e}")
    return ["", " ", "\n", "NULL", "<script>alert(1)</script>"]


def make_random_value(naughty_strings):
    choice = random.randint(0, 13)

    if choice == 0:
        return random.randint(-1000, 1000)
    elif choice == 1:
        return random.uniform(-1000, 1000)
    elif choice == 2:
        return str(random.randint(0, 9999))
    elif choice == 3:
        return random_alnum_string()
    elif choice == 4:
        return random.choice(naughty_strings)
    elif choice == 5:
        return None
    elif choice == 6:
        return [1, 2, 3]
    elif choice == 7:
        return {"k": "v"}
    elif choice == 8:
        return {1, 2}
    elif choice == 9:
        return (1, 2)
    elif choice == 10:
        return b"abc"
    elif choice == 11:
        return ValueErrorMul()
    elif choice == 12:
        return ZeroDivMul()
    else:
        return RuntimeMul()


def random_alnum_string(min_len=1, max_len=12):
    length = random.randint(min_len, max_len)
    chars = string.ascii_letters + string.digits
    s = ""
    for _ in range(length):
        s += random.choice(chars)
    return s


if __name__ == '__main__':
    simpleFuzzer()
