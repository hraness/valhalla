#!/usr/bin/env python3
"""Exploratory pinned Unicode 16 oracle; not part of the production protocol.

This is NFKC + casefold + NFKC, not an implementation claim for Unicode's formal
NFKC_Casefold mapping (which also removes default-ignorable characters).
"""
import json
import unicodedata as u
assert u.unidata_version == '16.0.0', 'pin the oracle; never silently use host Unicode'
values = ['Rust', 'É', 'E\u0301', 'İ', 'i', 'ß', 'ss', 'Ｒust', 'а', 'a']
print(json.dumps({
    'unicode_version': u.unidata_version,
    'experimental_algorithm': 'NFKC(CaseFold(NFKC(input)))',
    'values': [{'input': s, 'key': u.normalize('NFKC', u.normalize('NFKC', s).casefold())} for s in values],
}, ensure_ascii=True, indent=2))
