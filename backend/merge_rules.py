import json
import os

SUGGESTED_FILE = 'suggested_rules.json'
RULES_FILE = 'rules.json'

def load_json(path):
    if not os.path.exists(path):
        return []
    with open(path, 'r') as f:
        return json.load(f)

def save_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def rule_key(rule):
    # A unique identifier for a rule (used for deduping)
    return f"{rule['type']}|{rule['contains']}|{rule['label']}"

def merge_rules(existing, suggested):
    existing_keys = set(rule_key(r) for r in existing)
    new_rules = [r for r in suggested if rule_key(r) not in existing_keys]
    merged = existing + new_rules
    return merged, new_rules

def main():
    existing_rules = load_json(RULES_FILE)
    suggested_rules = load_json(SUGGESTED_FILE)

    merged_rules, new_rules = merge_rules(existing_rules, suggested_rules)

    if not new_rules:
        print("No new rules to merge - you're all caught up.")
        return

    save_json(RULES_FILE, merged_rules)

    print(f"Merged {len(new_rules)} new rule(s) into rules.json:")
    for rule in new_rules:
        print(f"  - [{rule['type']}] '{rule['contains']}' -> {rule['label']}")

if __name__ == '__main__':
    main()
