import csv
import statistics
import sys


def main(path):
    with open(path, newline="") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        print("empty file")
        return
    print(f"rows: {len(rows)}")
    print(f"columns: {', '.join(rows[0].keys())}")
    for col in rows[0]:
        vals = []
        for r in rows:
            try:
                vals.append(float(r[col]))
            except (TypeError, ValueError):
                break
        else:
            print(f"{col}: min={min(vals):g} max={max(vals):g} mean={statistics.fmean(vals):g}")


if __name__ == "__main__":
    main(sys.argv[1])
