import random
import string
import json
from datetime import datetime
from pathlib import Path

def multiply(v1, v2):
    return v1 * v2 

def simpleFuzzer():
    max_errors = 10
    errors_collected = []
    seen_signatures = set()

    naughty_strings = load_naughty_strings("blns.json")

    total_tests = 2000  # more tries so we can hit more weird combos

    for _ in range(total_tests):
        # 1) sometimes mess up the *arity* to force different errors
        call_kind = random.randint(0, 6)

        v1 = make_random_value(naughty_strings)
        v2 = make_random_value(naughty_strings)
        v3 = make_random_value(naughty_strings)

        try:
            if call_kind == 0:
                # normal call
                multiply(v1, v2)
            elif call_kind == 1:
                # missing arg
                multiply(v1)
            elif call_kind == 2:
                # too many args
                multiply(v1, v2, v3)
            else:
                # mostly normal calls but with weirder values
                multiply(v1, v2)
        except Exception as e:
            # make signature more specific so similar errors count as diff
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

    with open("collected_errors.txt", "w", encoding="utf-8") as f:
        for err in errors_collected:
            f.write(json.dumps(err, ensure_ascii=False) + "\n")

    print(f"Fuzzing done. Collected {len(errors_collected)} errors in collected_errors.txt")


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

    # fallback
    return [
        "",
        " ",
        "\n",
        "NULL",
        "admin' OR '1'='1",
        "../../../../etc/passwd",
        "<script>alert(1)</script>",
        "\"",
        "'",
        "🔥",
    ]


def make_random_value(naughty_strings):
    """
    Return a value from lots of types so we trigger different error messages.
    """
    choice = random.randint(0, 11)

    if choice == 0:
        return random.randint(-1000, 1000)         # int
    elif choice == 1:
        return random.uniform(-1000, 1000)         # float
    elif choice == 2:
        return str(random.randint(0, 9999))        # number-like str
    elif choice == 3:
        return random_alnum_string()               # random str
    elif choice == 4:
        return random.choice(naughty_strings)      # BLNS
    elif choice == 5:
        return None
    elif choice == 6:
        return [random.randint(0, 5), "x"]         # list
    elif choice == 7:
        return {"k": "v"}                          # dict
    elif choice == 8:
        return {1, 2, 3}                           # set
    elif choice == 9:
        return (1, 2)                              # tuple
    elif choice == 10:
        return b"abc"                              # bytes
    else:
        return complex(1, 2)                       # complex number


def random_alnum_string(min_len=1, max_len=12):
    length = random.randint(min_len, max_len)
    chars = string.ascii_letters + string.digits
    s = ""
    for _ in range(length):
        s += random.choice(chars)
    return s


if __name__=='__main__':
    simpleFuzzer()
