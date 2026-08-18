#!/usr/bin/env python3

import argparse
import hashlib
import re
from pathlib import Path


IP_PATTERN = re.compile(
    r"\b(?:"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
    r"){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b"
)

HASH_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"       # MD5
    r"|\b[a-fA-F0-9]{40}\b"      # SHA-1
    r"|\b[a-fA-F0-9]{64}\b"      # SHA-256
)


def extract_iocs(text):
    """Extract common indicators of compromise from text."""

    iocs = {
        "IPs": set(IP_PATTERN.findall(text)),
        "URLs": set(URL_PATTERN.findall(text)),
        "Emails": set(EMAIL_PATTERN.findall(text)),
        "Domains": set(DOMAIN_PATTERN.findall(text)),
        "Hashes": set(HASH_PATTERN.findall(text)),
    }

    # Remove domains that are already part of URLs.
    for url in iocs["URLs"]:
        domain_match = re.search(r"https?://([^/:]+)", url)
        if domain_match:
            iocs["Domains"].discard(domain_match.group(1))

    # Remove domains that are actually email domains.
    for email in iocs["Emails"]:
        iocs["Domains"].discard(email.split("@")[-1])

    return iocs


def print_report(iocs):
    """Display extracted IOCs in a readable format."""

    print("\n=== IOC EXTRACTION REPORT ===")

    total = 0

    for category, values in iocs.items():
        print(f"\n{category}:")

        if not values:
            print("  None found")
            continue

        for value in sorted(values):
            print(f"  - {value}")

        total += len(values)

    print(f"\nTotal IOCs: {total}")


def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of the input file."""

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description="Extract common IOCs from a text file."
    )

    parser.add_argument(
        "file",
        help="Path to the file containing suspicious text"
    )

    args = parser.parse_args()

    file_path = Path(args.file)

    if not file_path.is_file():
        print(f"[!] File not found: {file_path}")
        return

    try:
        text = file_path.read_text(
            encoding="utf-8",
            errors="ignore"
        )
    except OSError as error:
        print(f"[!] Could not read file: {error}")
        return

    print(f"[*] Analyzing: {file_path}")
    print(f"[*] File SHA-256: {calculate_file_hash(file_path)}")

    iocs = extract_iocs(text)

    print_report(iocs)


if __name__ == "__main__":
    main()
