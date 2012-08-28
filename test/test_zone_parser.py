import unittest

from bsa.zone import ZoneParser
from bsa.zone import A

ZONE1 = """
$ORIGIN example.com.
. A 1.1.1.1
  42 A 1.1.1.1
  CH A 1.1.1.1
  42 CH A 1.1.1.1
  CH 42 A 1.1.1.1

; same origin, new
www A 1.1.1.1
    42 A 1.1.1.1
    CH A 1.1.1.1
    42 CH A 1.1.1.1
    CH 42 A 1.1.1.1

; switch of origin
$ORIGIN other.com.
www A 1.1.1.1
    A 1.1.1.1
"""

ZONE1_EXPECTED = [
    A((".", None, None, "example.com.", ""), "1.1.1.1"),
    A((".", 42, None, "example.com.", ""), "1.1.1.1"),
    A((".", None, "CH", "example.com.", ""), "1.1.1.1"),
    A((".", 42, "CH", "example.com.", ""), "1.1.1.1"),
    A((".", 42, "CH", "example.com.", ""), "1.1.1.1"),

    A(("www", None, None, "example.com.", ""), "1.1.1.1"),
    A(("www", 42, None, "example.com.", ""), "1.1.1.1"),
    A(("www", None, "CH", "example.com.", ""), "1.1.1.1"),
    A(("www", 42, "CH", "example.com.", ""), "1.1.1.1"),
    A(("www", 42, "CH", "example.com.", ""), "1.1.1.1"),

    # Origin change
    A(("www", None, "IN", "other.com.", ""), "1.1.1.1"),

    # Implicit RR rule, inherit label from previous RR.
    A(("www", None, "IN", "other.com.", ""), "1.1.1.1"),
]


class TestZoneParser(unittest.TestCase):
    def test_1(self):
        parser = ZoneParser("test.zone")
        for ref, actual in zip(ZONE1_EXPECTED, parser.parseString(ZONE1)):
            self.assertEquals(ref, actual)
