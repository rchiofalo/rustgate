# rustgate documentation site

This directory is an [mdBook](https://rust-lang.github.io/mdBook/)
project that builds the public rustgate documentation site published
to GitHub Pages.

## Build locally

```bash
cargo install mdbook mdbook-mermaid mdbook-admonish mdbook-toc mdbook-linkcheck
cd docs-site
mdbook-mermaid install .
mdbook-admonish install .
mdbook serve --open
```

## Layout

- `book.toml` — mdBook configuration
- `src/SUMMARY.md` — site navigation (the single source of truth)
- `src/` — all content, organized by top-level section
- `theme/` — custom CSS + mermaid bootstrap JS

## Deploy

Pushes to `main` trigger `.github/workflows/docs.yml`, which builds
the book plus `cargo doc --workspace --no-deps` and deploys the
combined artifact to GitHub Pages. The rustdoc is mounted at
`/api/rustdoc/`.
