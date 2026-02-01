#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError as exc:
    sys.stderr.write("jsonschema is required; install python3-jsonschema or pip install jsonschema\n")
    sys.exit(1)


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate event samples against schema")
    parser.add_argument("--schema", required=True, help="Path to JSON schema")
    parser.add_argument("--samples", required=True, help="Path to samples directory")
    args = parser.parse_args()

    schema_path = Path(args.schema)
    samples_dir = Path(args.samples)

    schema = load_json(schema_path)
    validator = jsonschema.Draft202012Validator(schema)

    failures = 0
    for sample_path in sorted(samples_dir.glob("*.json")):
        sample = load_json(sample_path)
        errors = sorted(validator.iter_errors(sample), key=lambda e: e.path)
        if errors:
            failures += 1
            sys.stderr.write(f"Schema validation failed: {sample_path}\n")
            for err in errors:
                loc = "/".join(str(p) for p in err.path) or "<root>"
                sys.stderr.write(f"  - {loc}: {err.message}\n")

    if failures:
        return 1

    print(f"Validated {len(list(samples_dir.glob('*.json')))} samples against schema")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
