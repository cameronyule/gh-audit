# gh-audit

Personal GitHub repository meta linting tool for consistent configuration.

## Usage

```sh
$ nix develop

$ uv run gh-audit --help
Usage: gh-audit [OPTIONS] [REPOSITORY]...

Options:
  --active              Include all your non-archived repositories
  --github-token TOKEN  GitHub API token  [required]
  --verbose             Enable debug logging
  --rule RULE           Specify rules to run
  --format [repo|rule]  [required]
  --version             Show the version and exit.
  --help                Show this message and exit.
```
