import argparse
from pathlib import Path
from .analyzer import analyze
from .io import load_events
from .reporting import markdown_report


def main() -> None:
    p = argparse.ArgumentParser(description="Analyze normalized synthetic security logs")
    p.add_argument("input")
    p.add_argument("--output", default="assessment.md")
    args = p.parse_args()
    report = markdown_report(analyze(load_events(args.input)))
    Path(args.output).write_text(report, encoding="utf-8")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
