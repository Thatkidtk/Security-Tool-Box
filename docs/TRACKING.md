# Tracking Plan

This document outlines initial issues to track in GitHub. Create them using the issue templates.

Core
- Web fingerprints: expand rules (headers, meta generator, body markers), add favicon hash (MurMur/xxhash) [feature]
- Scan: add `--host-concurrency` for multi-host parallel scans with global QPS [feature]
- UDP: add SNMP sysName/sysObjectID, DNS `version.bind`, NTP refid parse [feature]
- Banner: `--max-redirects` and `--timeout-handshake` [feature]

Forensics
- Add PCAP detection + SHA1, file entropy metric, and CSV export [feature]
- Add directory walk + ignore patterns [feature]

Credentials
- Add known hash parsers (sha1:username, htpasswd, netntlmv2 capture parsing) [feature]
- Add wordlist normalizer (lowercase, strip, Unicode NFKC option) [feature]

Tooling
- Warning cleanup for narrow feature builds [chore]
- README: add full CLI reference and examples [docs]

Project Board
- Create a GitHub Project (v2) named "Roadmap" with columns: Backlog, In Progress, Done.
- Add the issues above to the board.

