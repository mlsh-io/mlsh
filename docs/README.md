# MLSH Documentation Site

English documentation for MLSH, built with [Zola](https://www.getzola.org/) and published at [docs.mlsh.io](https://docs.mlsh.io).

## Local development

```sh
make docs-serve      # runs `zola serve` in this directory
# → http://127.0.0.1:1111
```

Or directly:

```sh
cd docs && zola serve
```

## Build

```sh
make docs-build                           # zola build
make docs-build-with-search               # zola build + pagefind index
```

## Structure

```
docs/
  config.toml            # Zola config
  content/               # Markdown source, organized by section
    getting-started/
    cli/
    signal-server/
    security/
    networking/
    troubleshooting/
    reference/
  templates/             # Tera templates (base, index, section, page, partials/sidebar)
  sass/style.scss        # SCSS compiled at build time (compile_sass = true)
  static/
    tokens.css           # MLSH design system — colors, type, spacing
    logo.svg, favicon.*  # Brand assets
    js/                  # copy-code, theme-toggle, search, version-picker
  Containerfile          # Optional local preview container
```

## Versioning

Every git tag `vX.Y.Z` is built and deployed under `docs.mlsh.io/vX.Y.Z/` by `.github/workflows/docs.yml`. The site root redirects to the latest version; a version picker in the header switches between them. See the workflow for the deploy pipeline.

## Contributing

All pages are Markdown with a TOML front-matter. `weight` controls the order in the sidebar, `title` and `description` are consumed by the templates and search index.

Edit a page in place and open a PR — the rendered preview will appear at the next release build.
