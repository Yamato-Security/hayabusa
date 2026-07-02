#!/usr/bin/env python3
"""Sync the field-modifier / correlation count tables in the docs from upstream.

The canonical counts of how often each field modifier and correlation rule is
used in the Sigma and Hayabusa rulesets are generated in the hayabusa-rules repo
at ``doc/SupportedSigmaFieldModifiers.md`` (regenerated there whenever the rules
change). The docs page ``website/docs/rules/field-modifiers.md`` and its
translations embed those tables as a snapshot.

This script pulls the upstream file and replaces the Markdown tables in every
``field-modifiers*.md`` docs page, leaving the localized headings and prose
untouched — only the numeric tables (which are identical across languages) are
updated.

Limitation: it replaces the existing tables in place, so it tracks value/row
changes but does not add or remove whole sections. If upstream ever changes the
number of tables, the affected file is skipped (and reported) rather than
corrupted.

Run from anywhere:  python website/scripts/sync_field_modifiers.py
"""
import glob
import os
import sys
import urllib.request

UPSTREAM_URL = (
    "https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/"
    "main/doc/SupportedSigmaFieldModifiers.md"
)
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOCS_GLOB = os.path.join(ROOT, "website", "docs", "rules", "field-modifiers*.md")


def table_blocks(lines):
    """Return (start, end) index ranges of contiguous Markdown-table blocks
    (maximal runs of lines whose first non-space character is ``|``)."""
    blocks = []
    start = None
    for i, line in enumerate(lines):
        if line.lstrip().startswith("|"):
            if start is None:
                start = i
        elif start is not None:
            blocks.append((start, i))
            start = None
    if start is not None:
        blocks.append((start, len(lines)))
    return blocks


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "hayabusa-docs-sync"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8").replace("\r\n", "\n")


def main():
    up_lines = fetch(UPSTREAM_URL).split("\n")
    up_tables = [up_lines[s:e] for s, e in table_blocks(up_lines)]
    if not up_tables:
        sys.exit("No tables found in the upstream document; aborting.")

    changed = []
    for path in sorted(glob.glob(DOCS_GLOB)):
        original = open(path, encoding="utf-8").read()
        lines = original.replace("\r\n", "\n").split("\n")
        blocks = table_blocks(lines)
        name = os.path.basename(path)
        if len(blocks) != len(up_tables):
            print(
                f"SKIP {name}: {len(blocks)} table block(s) but upstream has "
                f"{len(up_tables)} — structure changed, update the page manually."
            )
            continue
        # Replace from the last block to the first so earlier indices stay valid.
        # Keep each file's own header + separator rows (which may be localized, e.g.
        # translated column headers) and replace only the data rows, so the sync
        # updates the counts without undoing any translation work.
        for (start, end), table in zip(reversed(blocks), reversed(up_tables)):
            if end - start >= 2 and len(table) >= 2:
                lines[start + 2:end] = table[2:]
            else:
                lines[start:end] = table
        updated = "\n".join(lines)
        if not updated.endswith("\n"):
            updated += "\n"
        if updated != original:
            open(path, "w", encoding="utf-8").write(updated)
            changed.append(name)

    if changed:
        print("Updated field-modifier tables in:", ", ".join(changed))
    else:
        print("Field-modifier tables already up to date.")


if __name__ == "__main__":
    main()
