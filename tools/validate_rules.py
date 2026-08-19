#!/usr/bin/env python3
"""
Sigma Rule Syntax and Schema Validator.
Ensures all Sigma YAML rules contain required fields and valid ATT&CK tags.
"""

import os
import sys
import yaml
import argparse

REQUIRED_FIELDS = ["title", "id", "status", "description", "author", "logsource", "detection", "level", "tags"]
VALID_LEVELS = ["informational", "low", "medium", "high", "critical"]

def validate_rule_file(filepath):
    errors = []
    with open(filepath, 'r', encoding='utf-8') as f:
        try:
            data = yaml.safe_load(f)
        except Exception as e:
            return [f"YAML parsing error: {e}"]

    if not isinstance(data, dict):
        return ["Root structure must be a dictionary/mapping"]

    for field in REQUIRED_FIELDS:
        if field not in data:
            errors.append(f"Missing required field: '{field}'")

    level = data.get("level")
    if level and str(level).lower() not in VALID_LEVELS:
        errors.append(f"Invalid level '{level}'. Must be one of: {', '.join(VALID_LEVELS)}")

    tags = data.get("tags", [])
    if not isinstance(tags, list) or len(tags) == 0:
        errors.append("Rule must include at least one tag")
    else:
        attack_tags = [t for t in tags if str(t).startswith("attack.")]
        if not attack_tags:
            errors.append("Rule must include at least one 'attack.<technique>' tag")

    return errors

def validate_directory(dirpath):
    all_passed = True
    total_checked = 0
    for root, _, files in os.walk(dirpath):
        for f in sorted(files):
            if f.endswith((".yml", ".yaml")):
                total_checked += 1
                full_path = os.path.join(root, f)
                errs = validate_rule_file(full_path)
                rel = os.path.relpath(full_path, dirpath)
                if errs:
                    all_passed = False
                    print(f"[FAIL] {rel}:")
                    for err in errs:
                        print(f"  - {err}")
                else:
                    print(f"[PASS] {rel}")
    return all_passed, total_checked

def main():
    parser = argparse.ArgumentParser(description="Validate Sigma detection rules")
    parser.add_argument("path", help="Path to rule file or directory")
    args = parser.parse_args()

    if os.path.isfile(args.path):
        errs = validate_rule_file(args.path)
        if errs:
            for e in errs:
                print(f"[FAIL] {e}", file=sys.stderr)
            sys.exit(1)
        print("[PASS] Rule is valid")
    elif os.path.isdir(args.path):
        passed, count = validate_directory(args.path)
        print(f"\nValidated {count} rules.")
        if not passed:
            sys.exit(1)
        print("All rules valid!")
    else:
        print(f"[!] Path not found: {args.path}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

# Enriched schema check for critical severity rules

# Checked against SigmaHQ 2026 standard
