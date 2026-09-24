"""Independent qualification oracle checks, without processes or live data."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import qualify_private_generation as g


def native():
    context = b"".join(bytes([n]) * 32 for n in range(1, 5))
    original = bytes([5])*32
    controller = hashlib.sha256(b"vhalla/private/controller-id/v1\0"+context+original).digest()
    number = lambda n:n.to_bytes(8,"big")
    raw = b"VHCDRAIN\x01"+context+controller+original+bytes([6])*32+number(0)
    raw += bytes([7])*32+bytes([8])*32+original+number(3)+bytes([9])*32+number(5)+number(2)+bytes([10])*32+b"\0"
    raw += b"".join(number(n) for n in (5,3,4,100,6,2,1))+bytes([11])*32
    raw += b"".join(number(n) for n in (2,0,2,200,2,0,0))+bytes([12])*32
    return raw+number(1000)+number(1000)+bytes(32)


class GenerationOracles(unittest.TestCase):
    def test_native_format_binds_identity_heads_and_complete_bytes(self):
        raw=native()
        value=g.native_receipt(raw)
        self.assertEqual(value["generation"],0)
        self.assertEqual(value["terminal_head"],3)
        self.assertEqual(value["normal"]["charged_attempts"],6)
        self.assertEqual(value["controls"]["canonical_bytes"],200)
        self.assertEqual(value["receipt_commitment"],hashlib.sha256(b"vhalla/private/controller-pause-receipt/v1\0"+raw).hexdigest())
        for offset in (0,137,337,377,385,425,433):
            altered=bytearray(raw);altered[offset]^=1
            with self.subTest(offset=offset),self.assertRaises(g.runtime.MeasurementError):
                g.native_receipt(altered)
        for size in (0,9,425,546,649):
            with self.subTest(size=size),self.assertRaises(g.runtime.MeasurementError):
                g.native_receipt(raw[:size])
        with self.assertRaises(g.runtime.MeasurementError):g.native_receipt(raw+b"\0")

    def test_carry_rejects_reset_new_identity_and_implicit_authority(self):
        old={"a":{"spent_items":4,"spent_bytes":100,"authorized_items":10,"authorized_bytes":1000,"max_items":10,"max_bytes":1000}}
        g.carry_checked(old,copy.deepcopy(old),exact=True)
        grown=copy.deepcopy(old);grown["a"]["spent_items"]+=1;grown["a"]["spent_bytes"]+=20
        g.carry_checked(old,grown)
        with self.assertRaises(g.runtime.MeasurementError):g.carry_checked(old,grown,exact=True)
        for field in old["a"]:
            altered=copy.deepcopy(old)
            altered["a"][field]+= -1 if field.startswith("spent") else 1
            with self.subTest(field=field),self.assertRaises(g.runtime.MeasurementError):g.carry_checked(old,altered)
        with self.assertRaises(g.runtime.MeasurementError):g.carry_checked(old,{})
        with self.assertRaises(g.runtime.MeasurementError):g.carry_checked(old,{**old,"b":old["a"]})

    def test_original_evidence_must_stay_byte_identical(self):
        g.preserved({"image":"a","cipher":"b"},{"image":"a","cipher":"b","pause":"c"})
        for after in ({"image":"a"},{"image":"a","cipher":"new"}):
            with self.assertRaises(g.runtime.MeasurementError):g.preserved({"image":"a","cipher":"b"},after)


if __name__ == "__main__":unittest.main()
