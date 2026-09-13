#!/usr/bin/env python3
"""Independent content-ID and envelope-layout oracle for committed golden bytes."""
import hashlib
from pathlib import Path
root = Path(__file__).parent / 'vectors'
for name, version in [('legacy-post-v1',1),('faceted-post-v1',1),('faceted-post-v2',2),('faceted-revision-v1',1)]:
    raw = bytes.fromhex((root/f'{name}.hex').read_text())
    size = int.from_bytes(raw[:4], 'big')
    unsigned = raw[4:4+size]
    assert len(raw) == 4+size+65 and raw[-1] == 0
    assert unsigned[:5] == b'VHSO' + bytes([version])
    actual = hashlib.sha256(f'vhalla/social/content-id/v{version}'.encode()+unsigned).hexdigest()
    assert actual == (root/f'{name}.id').read_text().strip()
    print(f'{name}: {len(raw)} bytes, content ID {actual}')
# The expanded opcodes are the only changed pre-facet byte in the original body.
legacy = bytes.fromhex((root/'legacy-post-v1.hex').read_text())
new = bytes.fromhex((root/'faceted-post-v1.hex').read_text())
a = legacy[4:4+int.from_bytes(legacy[:4],'big')]
b = new[4:4+int.from_bytes(new[:4],'big')]
assert [(i,x,y) for i,(x,y) in enumerate(zip(a,b)) if x != y] == [(128,0,8)]
print(f'extension: {len(b)-len(a)} bytes; legacy operation prefix otherwise identical')
