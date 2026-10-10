---
name: csv-summary
description: Summarize a CSV file in the workspace (row count, columns, numeric min/max/mean). Use when someone asks for a quick look at a spreadsheet export.
---
# CSV Summary

Run the bundled script on the file the user points at:

```bash
python3 scripts/summarize.py data/input.csv > data/summary.txt
cat data/summary.txt
```

Then read `data/summary.txt` back to the user in a sentence or two.
