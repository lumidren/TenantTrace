# Performance

Measured with `python scripts/perf_run.py` on the machine that built this repository. The input is
synthetic: the demo tenant's audit activity replicated across fictional accounts in one Purview-layout
CSV, next to the demo's own exports. It measures throughput and memory, not detection quality.

- Machine: Windows-11-10.0.26200-SP0, Intel64 Family 6 Model 154 Stepping 3, GenuineIntel, 20 logical CPUs
- Python 3.12.10 (64bit)
- Input: 1,000,000 generated audit records for 511 accounts in one CSV of 1,240 MB, plus the demo exports
- Records ingested: 1,002,149 parsed of 1,002,149 (0 unrecognised, 0 malformed)
- Case database: 1,289 MB
- Generating the input took 23 s (not part of the pipeline)

| Stage | Seconds | Peak memory of the process so far (MB) |
|---|---|---|
| ingest | 87.1 | 41 |
| coverage | 9.6 | 41 |
| analyze | 18.0 | 41 |
| report (HTML, PDF, JSON) | 0.9 | 56 |
| **Total** | **115.6** | **56** |

Analysis result on top of the large tenant: 12 findings (confirmed 10, probable 2), pivot accounts: marcus.oyelaran@harborlane.example.

Parsing streams records and keeps only a bounded buffer, so memory does not grow with the size of the
input file; it grows with what the case database query results hold for the account under analysis.
