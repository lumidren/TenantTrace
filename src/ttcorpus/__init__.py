"""ttcorpus: synthetic Microsoft 365 export generator for TenantTrace tests.

This package must never import from `tenanttrace`. Its writers are built from the
documented export layouts in docs/sources/, separately from TenantTrace's parsers, so that
tests compare two independent readings of the same documentation rather than the tool
agreeing with itself. tests/test_corpus_independence.py enforces the import boundary.

All people, organisations, domains and IP addresses are fictional: domains use the
reserved `.example` TLD and example.com/net/org, IPv4 addresses come from the
documentation ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24, and IPv6 from
2001:db8::/32.
"""

GENERATOR_VERSION = "1.0"
