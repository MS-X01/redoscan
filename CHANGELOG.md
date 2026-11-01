# Changelog

## 1.1.0

### Added
- **New HTML report**: banner with project and author links, severity donut, breakdowns by category /
  language / file, live search with highlighting, filters (severity, category, language, file,
  confidence), grouping (category / file / language / severity / none), sorting, expand / collapse,
  copy buttons, CSV and JSON export, light / dark theme, print styles. Still one self-contained file.
- Paths in the HTML report are relative to the scanned directory.
- CWE-1333 reference on ReDoS findings in the HTML report.
- `CHANGELOG.md`, `CONTRIBUTING.md`, issue templates.

### Changed
- **`--help` rewritten in classic Unix style**: `--format, -f {terminal,json,html}` (long option, alias,
  value placeholder once), grouped into Target / Analysis / Filtering / Output / CI / Misc, with
  examples, exit status and file notes.
- README rewritten (banner, screenshots, recipes, CI snippet, FAQ, language matrix).

### Fixed
- `--no-color` no longer leaks raw ANSI escape codes into piped / saved output.
- `--list-categories` columns align for long names.

## 1.0.0
- Initial release: static + dynamic ReDoS engine, 11 vulnerability categories, 10 languages, terminal /
  JSON / HTML output, CI gating.
