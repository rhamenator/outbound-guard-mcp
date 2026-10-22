# Pinned IANA special-address registry snapshots

Retrieved 2026-10-22 from the authoritative IANA CSV endpoints:

- IPv4: https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv
- IPv6: https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv

Original CSV bytes (including line endings) are retained. SHA256 identities are pinned in `tools/iana_ip_policy_probe.py`. No registry is fetched during tests. Refresh requires reviewing the upstream changes, updating the hashes and rerunning the differential check; this snapshot cannot establish future registry assignments.

The independent data oracle is the most-specific matching row's `Globally Reachable` value. Only explicit `False` rows require denial. `True`, `N/A`, blank deprecated flags and addresses outside these registries do not imply an allow requirement. The script uses Python's standard-library `ipaddress` CIDR membership, rather than the Rust implementation's byte comparisons, with endpoint/adjacent and 256 seeded samples per registry CIDR. Two explicit public positive controls detect an always-deny adapter. This is a finite classifier comparison, not an independent security audit, coverage-guided fuzzing or observed socket test. Existing Rust properties and controlled DNS/socket fixtures remain separate.

IPv6 corpus addresses use explicit eight-group hexadecimal serialization, including mapped addresses. This avoids Python-version changes in their default presentation. Local and CI corpus byte identities must be compared, not inferred from a matching sample count.
