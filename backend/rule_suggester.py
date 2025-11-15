import json
import os
from collections import defaultdict, Counter
import re
from email.utils import parseaddr

EXAMPLES_FILE = 'labeled_examples.jsonl'
SUGGESTED_FILE = 'suggested_rules.json'

GENERIC_DOMAINS = {
    "gmail", "yahoo", "hotmail", "aol", "outlook", "msn", "icloud", "live", "me"
}

def get_domain_root(from_field):
    name, email = parseaddr(from_field)
    match = re.search(r'@([\w.-]+)', email)
    if match:
        full_domain = match.group(1).lower()
        parts = full_domain.split('.')
        if len(parts) >= 2:
            domain_root = parts[-2]
            return domain_root
    return None

def load_examples():
    if not os.path.exists(EXAMPLES_FILE):
        return []
    with open(EXAMPLES_FILE, 'r') as f:
        return [json.loads(line) for line in f]

def generate_suggestions(examples, min_count=2):
    domain_to_labels = defaultdict(set)
    domain_counts = defaultdict(Counter)

    subject_to_labels = defaultdict(set)
    subject_counts = defaultdict(Counter)

    for ex in examples:
        label = ex['label']
        sender = ex['from']
        subject = ex['subject'].strip()

        domain_root = get_domain_root(sender)
        if domain_root and domain_root not in GENERIC_DOMAINS:
            domain_to_labels[domain_root].add(label)
            domain_counts[domain_root][label] += 1

        if subject:
            subject_to_labels[subject].add(label)
            subject_counts[subject][label] += 1

    suggestions = []

    # Domain-based rules
    for domain_root, labels in domain_to_labels.items():
        if len(labels) == 1:
            label = next(iter(labels))
            if domain_counts[domain_root][label] >= min_count:
                suggestions.append({
                    'type': 'from',
                    'contains': domain_root,
                    'label': label
                })

    # Subject-based rules
    for subject, labels in subject_to_labels.items():
        if len(labels) == 1:
            label = next(iter(labels))
            if subject_counts[subject][label] >= min_count:
                suggestions.append({
                    'type': 'subject',
                    'contains': subject,
                    'label': label
                })

    return suggestions

def save_suggestions(suggestions):
    with open(SUGGESTED_FILE, 'w') as f:
        json.dump(suggestions, f, indent=2)
    print(f"{len(suggestions)} smart rule suggestions saved to {SUGGESTED_FILE}")

def main():
    examples = load_examples()
    if not examples:
        print("No examples found.")
        return

    suggestions = generate_suggestions(examples)
    save_suggestions(suggestions)

if __name__ == '__main__':
    main()
