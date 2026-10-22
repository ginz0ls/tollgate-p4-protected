import unittest

from web.page import titolo


class WebTest(unittest.TestCase):
    def test_titolo(self):
        self.assertEqual(titolo(), "tollgate")

    def test_rotto(self):
        self.assertEqual(titolo(), "altro")
