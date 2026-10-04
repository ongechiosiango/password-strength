"""Rich terminal reporter for password strength."""

from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table

from .analyzer import Analysis
from .cracktime import ATTACK_LABELS, crack_times

console = Console()


SCORE_COLORS = ["red", "red", "yellow", "green", "bright_green"]
SCORE_BARS = ["", "█", "██", "███", "████"]


def print_report(analysis: Analysis) -> None:
    """Pretty-print the analysis."""
    console.print()
    console.rule("[bold cyan]Password Strength[/bold cyan]")

    color = SCORE_COLORS[analysis.score]
    bar = SCORE_BARS[analysis.score] or "▁"
    console.print(
        f"[bold]Score:[/bold] [{color}]{analysis.score}/4 - {analysis.label}[/{color}]  "
        f"[{color}]{bar}[/{color}]\n"
    )

    metrics = Table(show_header=True, header_style="bold magenta")
    metrics.add_column("Metric", style="cyan", no_wrap=True)
    metrics.add_column("Value", style="green")
    metrics.add_row("Length", str(analysis.password_length))
    metrics.add_row("Character pool", str(analysis.character_pool_size))
    metrics.add_row("Raw entropy", f"{analysis.raw_entropy_bits:.2f} bits")
    metrics.add_row("Adjusted entropy", f"{analysis.adjusted_entropy_bits:.2f} bits")
    console.print(metrics)

    times = crack_times(analysis.adjusted_entropy_bits)
    crack_table = Table(title="Estimated Crack Time", show_header=True, header_style="bold magenta")
    crack_table.add_column("Attack scenario", style="cyan", no_wrap=True)
    crack_table.add_column("Time", style="green")
    for scenario, human in times.items():
        crack_table.add_row(ATTACK_LABELS.get(scenario, scenario), human)
    console.print(crack_table)

    if analysis.penalties:
        console.print("[bold yellow]Weaknesses detected:[/bold yellow]")
        for p in analysis.penalties:
            console.print(f"  [yellow]-[/yellow] {p}")

    if analysis.suggestions:
        console.print("[bold cyan]Suggestions:[/bold cyan]")
        for s in analysis.suggestions:
            console.print(f"  [cyan]*[/cyan] {s}")


def to_json(analysis: Analysis) -> str:
    """Serialize an Analysis to a JSON string."""
    times = crack_times(analysis.adjusted_entropy_bits)
    payload = {
        "length": analysis.password_length,
        "character_pool_size": analysis.character_pool_size,
        "raw_entropy_bits": analysis.raw_entropy_bits,
        "adjusted_entropy_bits": analysis.adjusted_entropy_bits,
        "score": analysis.score,
        "label": analysis.label,
        "penalties": analysis.penalties,
        "suggestions": analysis.suggestions,
        "crack_times": times,
    }
    return json.dumps(payload, indent=2)
