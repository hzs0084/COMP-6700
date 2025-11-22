#!/usr/bin/env python3
import angr
import claripy

BINARY_PATH = "./comp5700"

# From objdump:
#   main:          0x9D8
#   success block: 0xA7C  -> offset 0xA4
#   failure block: 0xA98  -> offset 0xC0
SUCC_OFFSET = 0xA4
FAIL_OFFSET = 0xC0

def main():
    proj = angr.Project(BINARY_PATH, auto_load_libs=False)

    # Get rebased address of main so don't care about PIE/base
    main_sym = proj.loader.find_symbol("main")
    if main_sym is None:
        raise SystemExit("[-] Could not find symbol 'main' in the binary!")

    main_addr = main_sym.rebased_addr
    find_addr  = main_addr + SUCC_OFFSET
    avoid_addr = main_addr + FAIL_OFFSET

    print(f"[+] main    @ 0x{main_addr:x}")
    print(f"[+] success @ 0x{find_addr:x}")
    print(f"[+] failure @ 0x{avoid_addr:x}")

    # Program does: fgets(buf, 11, stdin)
    # -> up to 10 chars plus terminating '\0'
    # model 11 symbolic bytes from stdin.
    stdin_len = 11
    stdin_bytes = [claripy.BVS(f"stdin_byte_{i}", 8) for i in range(stdin_len)]
    stdin_sym = claripy.Concat(*stdin_bytes)

    # Initial state with symbolic stdin
    state = proj.factory.full_init_state(args=[BINARY_PATH], stdin=stdin_sym)

    # Optional: keep things printable (not strictly required)
    for b in stdin_bytes:
        state.solver.add(b >= 0x20)
        state.solver.add(b <= 0x7e)

    simgr = proj.factory.simgr(state)
    print("[*] Exploring to success block...")

    simgr.explore(find=find_addr, avoid=avoid_addr)

    if not simgr.found:
        print("[!] No path to success found. Try relaxing constraints or double-checking offsets.")
        return

    found = simgr.found[0]
    print("[+] Found a state reaching the success block!")

    # First 10 bytes will become the trimmed password (after newline handling)
    pw_bytes = stdin_bytes[:10]
    pw_concrete = found.solver.eval(claripy.Concat(*pw_bytes), cast_to=bytes)

    print("[+] Password bytes:", pw_concrete)
    try:
        print("[+] Password as string:", pw_concrete.decode("ascii"))
    except UnicodeDecodeError:
        print("[!] Password not clean ASCII; see raw bytes above.")

    # Show full stdin (all 11 bytes) sent to the program
    full_stdin = found.posix.dumps(0)
    print("[+] Full stdin to program:", full_stdin)

if __name__ == "__main__":
    main()
