# Password Strength

[![CI](https://github.com/ongechiosiango/password-strength/actions/workflows/ci.yml/badge.svg)](https://github.com/ongechiosiango/password-strength/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)

Estimate password strength using entropy, pattern detection, and crack-time estimates.

## Features

- Entropy-based scoring (raw + adjusted for known weaknesses).
- Detects repeated characters, sequential runs, keyboard walks, and common passwords.
- Score 0-4 mapped to Very Weak / Weak / Fair / Strong / Very Strong.
- Crack-time estimates at four realistic attack speeds.
- Interactive prompt (no echo), stdin mode, and JSON output.
- Zero network calls. Zero password storage.

## Installation

From source:

    git clone git@github.com:ongechiosiango/password-strength.git
    cd password-strength
    python3 -m venv venv
    source venv/bin/activate
    pip install -e ".[dev]"

## Usage

    password-strength

Or pipe from stdin:

    echo "MyPassword123" | password-strength --stdin

JSON output:

    echo "MyPassword123" | password-strength --json

See docs/usage.md for full details.

## Development

    pip install -e ".[dev]"
    pytest -v

## Contributing

See CONTRIBUTING.md.

## License

MIT - see LICENSE.
