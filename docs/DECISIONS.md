# Decisions

One line per decision: what was chosen, why, and the alternative that was not taken.

| # | Decision | Why | Alternative |
|---|----------|-----|-------------|
| 1 | argparse for the CLI | standard library, no extra dependency to audit | click/typer |
| 2 | Network blocked with a Python audit hook (`sys.addaudithook`) installed by the CLI | the guard cannot be removed once installed and covers dependencies too, not just our own code | relying on code review that no module opens sockets |
| 3 | Event IDs are hashes of (file SHA-256, record start line) | stable across reruns, so findings are reproducible and comparable | autoincrement row ids |
| 4 | `--force` only replaces a case folder containing nothing but TenantTrace's own files | avoids deleting an analyst's unrelated files by mistake | wiping the folder unconditionally |
| 5 | The case folder may not sit inside the input folder | the tool would otherwise hash and parse its own outputs | excluding it silently |
| 6 | Venv built from the 64-bit Python 3.12 (`py -3.12`), not the `python` on PATH | the PATH interpreter on this machine is 32-bit | using the 32-bit interpreter |
