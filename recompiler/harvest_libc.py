#!/usr/bin/env python3
"""Cross-reference Wine ucrtbase/msvcrt exports against macOS libSystem C99/C11 symbols."""

import json
from pathlib import Path
import ctypes

def main():
    root = Path(__file__).parent
    wine_db_path = root / "wine_api_db.json"
    if not wine_db_path.exists():
        print(f"Error: {wine_db_path} not found")
        return

    with open(wine_db_path) as f:
        wine_db = json.load(f)

    # All symbols known in Wine
    wine_symbols = set(wine_db.get("api_to_dll", {}).keys())

    # Load macOS libSystem
    libsystem = ctypes.CDLL("libSystem.B.dylib")

    # Math 1-arg double functions (XMM0 in, XMM0 out)
    math_1arg_candidates = [
        "sin", "cos", "tan", "asin", "acos", "atan",
        "sinh", "cosh", "tanh", "asinh", "acosh", "atanh",
        "exp", "exp2", "expm1", "log", "log10", "log2", "log1p",
        "sqrt", "cbrt", "ceil", "floor", "trunc", "round", "nearbyint", "rint",
        "fabs", "erf", "erfc", "lgamma", "tgamma"
    ]

    # Math 2-arg double functions (XMM0, XMM1 in, XMM0 out)
    math_2arg_candidates = [
        "atan2", "pow", "fmod", "hypot", "remainder", "copysign",
        "fdim", "fmax", "fmin"
    ]

    # Integer / Pointer libc candidates (RCX/RDX/R8/R9 in, RAX out)
    int_ptr_candidates = [
        # Memory
        "memchr", "memcmp", "memset", "memcpy", "memmove",
        # String
        "strcat", "strchr", "strcmp", "strcoll", "strcpy", "strcspn",
        "strdup", "strlen", "strncat", "strncmp", "strncpy", "strpbrk",
        "strrchr", "strspn", "strstr", "strtok", "strxfrm", "strnlen",
        # Ctype (ASCII safe)
        "isalnum", "isalpha", "isblank", "iscntrl", "isdigit", "isgraph",
        "islower", "isprint", "ispunct", "isspace", "isupper", "isxdigit",
        "tolower", "toupper",
        # Stdlib numeric conversions & search
        "atoi", "atol", "atoll", "strtol", "strtoll", "strtoul", "strtoull",
        "bsearch", "qsort", "abs", "labs", "llabs",
        "rand", "srand",
        # Time
        "time", "clock", "difftime"
    ]

    # Excluded explicitly:
    # - wchar_t functions (macOS wchar_t is 4 bytes, Windows is 2 bytes UTF-16)
    # - FILE* functions (macOS FILE struct layout differs from MSVCRT FILE struct)
    # - variadic functions (printf, sprintf, scanf)
    # - setjmp / longjmp
    # - locale-dependent or struct-pointer passing functions

    verified_float_1arg = []
    for fn in math_1arg_candidates:
        if fn in wine_symbols and hasattr(libsystem, fn):
            verified_float_1arg.append(fn)

    verified_float_2arg = []
    for fn in math_2arg_candidates:
        if fn in wine_symbols and hasattr(libsystem, fn):
            verified_float_2arg.append(fn)

    verified_int_ptr = []
    for fn in int_ptr_candidates:
        if fn in wine_symbols and hasattr(libsystem, fn):
            verified_int_ptr.append(fn)

    print(f"Verified float 1-arg functions: {len(verified_float_1arg)}")
    print(f"Verified float 2-arg functions: {len(verified_float_2arg)}")
    print(f"Verified int/ptr functions: {len(verified_int_ptr)}")

    # Update apis.json
    apis_path = root / "apis.json"
    with open(apis_path) as f:
        apis = json.load(f)

    # Merge while preserving existing custom adapters/stubs
    existing_f1 = set(apis.get("float_1arg", []))
    existing_f2 = set(apis.get("float_2arg", []))
    existing_pass = set(apis.get("passthrough", []))

    apis["float_1arg"] = sorted(list(existing_f1 | set(verified_float_1arg)))
    apis["float_2arg"] = sorted(list(existing_f2 | set(verified_float_2arg)))
    apis["passthrough"] = sorted(list(existing_pass | set(verified_int_ptr)))

    with open(apis_path, "w") as f:
        json.dump(apis, f, indent=2)

    print(f"Successfully updated {apis_path}")

if __name__ == "__main__":
    main()
