#!/usr/bin/env python3
"""Regenerate the docs Changelog pages from the repo's CHANGELOG files.

The Overview > Changelog pages mirror the root CHANGELOG.md /
CHANGELOG-Japanese.md. This script regenerates them so the published site is
always current. The docs deploy workflow runs it before `mkdocs build`; the
committed pages are a snapshot for local previews.

Run from anywhere:  python website/scripts/sync_changelog.py
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOCS = os.path.join(ROOT, "website", "docs", "overview")

NOTE_EN = (
    "!!! info\n"
    "    This page mirrors the project "
    "[`CHANGELOG.md`](https://github.com/Yamato-Security/hayabusa/blob/main/CHANGELOG.md). "
    "See the [Releases page](https://github.com/Yamato-Security/hayabusa/releases) for downloads."
)
NOTE_JA = (
    '!!! info "情報"\n'
    "    このページはプロジェクトの "
    "[`CHANGELOG.md`](https://github.com/Yamato-Security/hayabusa/blob/main/CHANGELOG-Japanese.md) "
    "を反映したものです。ダウンロードは "
    "[リリースページ](https://github.com/Yamato-Security/hayabusa/releases) をご覧ください。"
)

_LIST = re.compile(r'^([-*+]|\d{1,9}[.)])\s+\S')
_FENCE = re.compile(r'^\s*(```|~~~)')
_HEADING = re.compile(r'^#{1,6}\s')


def fix_tight_lists(text):
    """Insert a blank line before a top-level list that directly follows a
    top-level paragraph (Python-Markdown needs it; GitHub doesn't)."""
    out, in_fence = [], False
    for ln in text.split("\n"):
        if _FENCE.match(ln):
            in_fence = not in_fence
        if not in_fence and _LIST.match(ln) and out:
            p = out[-1]
            if (p.strip() and not _LIST.match(p) and not _HEADING.match(p)
                    and not p.lstrip().startswith(">") and not p.lstrip().startswith("|")
                    and not re.match(r'^\s', p)):
                out.append("")
        out.append(ln)
    return "\n".join(out)


def build(src, title, note, dest):
    lines = open(src, encoding="utf-8").read().split("\n")
    body = lines[1:]                      # drop the source's own top-level heading
    while body and body[0].strip() == "":
        body.pop(0)
    content = f"# {title}\n\n{note}\n\n" + "\n".join(body)
    content = fix_tight_lists(content).rstrip() + "\n"
    with open(dest, "w", encoding="utf-8") as f:
        f.write(content)
    print("wrote", os.path.relpath(dest, ROOT))


def main():
    build(os.path.join(ROOT, "CHANGELOG.md"), "Changelog", NOTE_EN,
          os.path.join(DOCS, "changelog.md"))
    build(os.path.join(ROOT, "CHANGELOG-Japanese.md"), "変更履歴", NOTE_JA,
          os.path.join(DOCS, "changelog.ja.md"))


if __name__ == "__main__":
    main()
