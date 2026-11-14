# NDJSON parser gaps

Rayhunter left 37702 message(s) undecoded across 487 NDJSON file(s), including 32283 encrypted NAS PDU(s). Those skips are capture-completeness notes. They are not pre-security IMSI Identity Requests.

- NDJSON files: 487
- Packet records: 50436
- Encrypted NAS message (skipped by Rayhunter): 32283
- Incomplete NAS message: 1762
- ServingCellTiming zero-record assertion: 70
- Unsupported LTE MAC framed: 80
- Other parser gap: 3507
- Encrypted NAS is a protected PDU. Rayhunter records the skip and
- does not expose an IMSI. Identity type is read from a plaintext
- Identity Request (nas-eps.emm.id_type2): 1=IMSI, 2=IMEI, 3=IMEISV, 4=TMSI.
