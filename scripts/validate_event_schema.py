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


def build_validator(schema: dict):
    # jsonschema<4 does not expose Draft202012Validator. Use the best available
    # validator for the declared $schema and gracefully fall back if needed.
    if hasattr(jsonschema, "Draft202012Validator"):
        return jsonschema.Draft202012Validator(schema)

    validators_mod = getattr(jsonschema, "validators", None)
    if validators_mod is not None and hasattr(validators_mod, "validator_for"):
        validator_cls = validators_mod.validator_for(schema)
        validator_cls.check_schema(schema)
        if validator_cls.__name__ != "Draft202012Validator":
            sys.stderr.write(
                f"warning: using {validator_cls.__name__}; "
                "Draft 2020-12 validator unavailable in installed jsonschema\n"
            )
        return validator_cls(schema)

    for name in ("Draft7Validator", "Draft6Validator", "Draft4Validator"):
        validator_cls = getattr(jsonschema, name, None)
        if validator_cls is not None:
            sys.stderr.write(
                f"warning: using {name}; "
                "Draft 2020-12 validator unavailable in installed jsonschema\n"
            )
            validator_cls.check_schema(schema)
            return validator_cls(schema)

    raise RuntimeError(
        "No suitable jsonschema validator available; install python3-jsonschema>=3.2"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate event samples against schema")
    parser.add_argument("--schema", required=True, help="Path to JSON schema")
    parser.add_argument("--samples", required=True, help="Path to samples directory")
    args = parser.parse_args()

    schema_path = Path(args.schema)
    samples_dir = Path(args.samples)

    schema = load_json(schema_path)
    validator = build_validator(schema)

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
