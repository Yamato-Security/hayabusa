# Hayabusa Documentation Site

A [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) site that turns
the Hayabusa `README.md` and the guides under `../doc/` into a browsable documentation
website — **main topics across the top, subtopics in the left sidebar** (the same
layout as <https://www.purplecloud.network/>).

It is designed to be hosted **for free on GitHub Pages**.

## Layout

```
website/
├── mkdocs.yml            # site config, theme, top-tab + sidebar navigation
├── requirements.txt      # pinned build dependencies
└── docs/
    ├── index.md          # landing page (hero + feature cards)
    ├── assets/           # logo + screenshots (copied from ../screenshots and ../doc)
    ├── stylesheets/      # custom CSS (falcon-blue theme)
    ├── overview/         # About, Main Goals, Features, Screenshots
    ├── getting-started/  # Downloads, Git Cloning, Compiling, Running
    ├── commands/         # Command list + Analysis / Config / DFIR Timeline reference
    ├── output/           # Output profiles, Abbreviations, Display & Summary
    ├── rules/            # Hayabusa rules
    ├── importing/        # Elastic Stack, Timesketch, Timeline Explorer, jq
    └── resources/        # Projects, Logging, Rust performance, Community, Contributing
```

## Preview locally

```bash
pip install -r website/requirements.txt
mkdocs serve -f website/mkdocs.yml
# open http://127.0.0.1:8000
```

Build a production copy (output goes to `website/site/`, which is git-ignored):

```bash
mkdocs build --strict -f website/mkdocs.yml
```

`--strict` fails the build on broken internal links or missing images — the same check
the CI workflow runs.

## Publish on GitHub Pages (one-time setup)

1. Push this `website/` folder and `.github/workflows/docs.yml` to your repo's `main`
   branch.
2. In GitHub: **Settings → Pages → Build and deployment → Source = "GitHub Actions"**.
3. Every push to `main` that changes `website/**` rebuilds and deploys automatically.
   You can also trigger it manually from the **Actions** tab (*Deploy docs to GitHub
   Pages → Run workflow*).

The site is served at `https://<your-user-or-org>.github.io/<repo>/`. If you host from
a different account/repo than the default, update `site_url`, `repo_url` and `repo_name`
at the top of `mkdocs.yml`.

## Updating content

Most pages are derived from the upstream `../README.md` and `../doc/*-English.md`
files. When those change, edit the corresponding page under `docs/` (each page maps to
a section of the README). Add or reorder pages by editing the `nav:` block in
`mkdocs.yml` — the top-level entries become the top tabs, and their children become the
sidebar for that tab.
