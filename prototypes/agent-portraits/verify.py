#!/usr/bin/env python3
"""Independent stdlib XML allowlist and canonical fixture verification."""
import hashlib
import json
import re
import sys
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(sys.argv[1])
NS = '{http://www.w3.org/2000/svg}'
COMMON = {'fill', 'stroke', 'stroke-width', 'stroke-linecap', 'stroke-linejoin', 'opacity'}
TAGS = {
 'svg': {'viewBox', 'width', 'height'}, 'defs': set(),
 'linearGradient': {'id', 'x1', 'y1', 'x2', 'y2'}, 'stop': {'offset', 'stop-color'},
 'pattern': {'id', 'width', 'height', 'patternUnits'} | COMMON,
 'g': {'transform'} | COMMON, 'path': {'d'} | COMMON,
 'circle': {'cx', 'cy', 'r'} | COMMON,
}
NUMERIC = {'width','height','x1','y1','x2','y2','cx','cy','r','stroke-width','opacity','offset'}
COLOR = re.compile(r'(?:#[0-9a-f]{6}|hsl\(\d{1,3} \d{1,2}% \d{1,2}%\)|none)')
REF = re.compile(r'url\(#(p[0-9a-f]{32}[012][01][gw])\)')
def check(raw):
 assert len(raw) <= 32768 and raw.isascii()
 assert b'<!' not in raw and b'<?' not in raw
 tree = ET.fromstring(raw)
 assert tree.tag == NS+'svg' and tree.attrib == {'viewBox':'0 0 128 128','width':'128','height':'128'}
 ids=set(); refs=set(); nodes=list(tree.iter())
 assert len(nodes) <= 96
 for node in nodes:
  assert node.tag.startswith(NS)
  tag=node.tag[len(NS):]
  assert tag in TAGS and set(node.attrib) <= TAGS[tag], (tag,node.attrib)
  assert not (node.text or '').strip() and not (node.tail or '').strip()
  for key,val in node.attrib.items():
   if key in NUMERIC:
    assert re.fullmatch(r'-?\d+(?:\.\d+)?',val)
    assert -128<=float(val)<=128
   elif key in ('fill','stroke','stop-color'):
    ref=REF.fullmatch(val)
    if ref: refs.add(ref.group(1))
    else: assert COLOR.fullmatch(val),val
   elif key=='id':
    assert re.fullmatch(r'p[0-9a-f]{32}[012][01][gw]',val) and val not in ids
    ids.add(val)
   elif key=='transform':assert re.fullmatch(r'translate\(-?\d+ -?\d+\)(?: rotate\(-?\d+\)| scale\(\d+\.\d{3}\) translate\(-?\d+ -?\d+\))?',val),val
   elif key=='d': assert re.fullmatch(r'[MLHVQCTZ0-9 .,-]+',val),val
   elif key=='patternUnits':assert val=='userSpaceOnUse'
   elif key=='viewBox':assert val=='0 0 128 128'
   elif key=='stroke-linecap':assert val=='round'
   elif key=='stroke-linejoin':assert val=='round'
   else:raise AssertionError(key)
 assert refs<=ids

files=sorted(ROOT.glob('family-*-agent-*.svg'))
assert len(files)==384
for p in files:check(p.read_bytes())
# These rejection tests exercise the verifier itself, not just the renderer.
valid=files[0].read_bytes()
for bad in [valid.replace(b'<defs>',b'<script>alert(1)</script><defs>'),valid.replace(b'<defs>',b'<image href="https://example.invalid"/><defs>'),valid.replace(b'<svg ',b'<svg onload="alert(1)" '),valid.replace(b'<defs>',b'<foreignObject/><defs>')]:
 try:check(bad)
 except AssertionError:pass
 else:raise AssertionError('unsafe SVG admitted by verifier')
vectors=json.loads((Path(__file__).parent/'tests/vectors.json').read_text())
for name,expected in vectors.items():assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==expected,name
print(f'PASS: {len(files)} bounded SVGs, XML allowlist, four unsafe mutations, {len(vectors)} golden vectors')
