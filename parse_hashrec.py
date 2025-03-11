import sys
import os

FNV_OFFSET_BASIS_64 = 0xcbf29ce484222325
FNV_PRIME_64 = 0x100000001b3

def fnv1a_hash_64(data):
    """Computes FNV-1a hash (64-bit)"""
    hash_val = FNV_OFFSET_BASIS_64
    for byte in data:
        hash_val ^= byte
        hash_val *= FNV_PRIME_64
        hash_val &= 0xFFFFFFFFFFFFFFFF
    return hash_val

def parse_hashrec(input_file, output_file):
    """Parses .hashrec file and generates .h file with FNV-1a 64-bit hashed values"""
    with open(input_file, "r") as f:
        lines = f.readlines()

    filename = os.path.splitext(os.path.basename(input_file))[0].upper()

    output_lines = [
        "/* Auto-generated from .hashrec */",
        f"#ifndef {filename}_HASHREC_GENERATED_H",
        f"#define {filename}_HASHREC_GENERATED_H",
        "",
        "#include <stdint.h>",
        ""
    ]

    for line in lines:
        line = line.strip()
        if not line or ":" not in line or "=" not in line:
            continue

        name, rest = line.split(":", 1)
        type_char, value = rest.split("=", 1)
        value = value.strip().strip('"')

        if type_char == "L":
            encoded_value = value.encode("utf-16le")
            print(f"Encoded (Wide) Value: {value} -> {encoded_value.hex()}")
            hash_value = fnv1a_hash_64(encoded_value)
        elif type_char == "N":
            encoded_value = value.encode("utf-8")
            print(f"Encoded (Normal) Value: {value} -> {encoded_value.hex()}")
            hash_value = fnv1a_hash_64(encoded_value)
        else:
            print(f"Warning: Unknown type '{type_char}' in {line}. Skipping.")
            continue

        output_lines.append(f"#define {name} 0x{hash_value:016X}  /* {value} */")

    output_lines.append(f"\n#endif /* {filename}_HASHREC_GENERATED_H */\n")

    with open(output_file, "w") as f:
        f.write("\n".join(output_lines))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 parse_hashrec.py <input.hashrec> <output.h>")
        sys.exit(1)

    parse_hashrec(sys.argv[1], sys.argv[2])
