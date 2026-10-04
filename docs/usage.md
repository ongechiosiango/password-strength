# Usage Guide

## Interactive prompt (recommended)

    password-strength

You will be prompted. Nothing is echoed, and the password is never
written to disk.

## From stdin

    echo "MyPassword123" | password-strength --stdin

## JSON output

    echo "MyPassword123" | password-strength --json

JSON output contains:

- length, character_pool_size
- raw_entropy_bits, adjusted_entropy_bits
- score (0-4), label
- penalties, suggestions
- crack_times (per attack scenario)

## Security notes

- The tool never logs or stores your password.
- Use --stdin only when piping from a trusted process.
- Avoid putting real passwords in shell history. Prefer the interactive prompt.
