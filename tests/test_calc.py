import unittest

from src.calc import somma, sottrai, moltiplica


class CalcTests(unittest.TestCase):
    def test_somma(self):
        self.assertEqual(somma(1, 2), 3)
        self.assertEqual(somma(0, 0), 0)

    def test_sottrai(self):
        self.assertEqual(sottrai(5, 3), 2)
        self.assertEqual(sottrai(0, 4), -4)

    def test_moltiplica(self):
        self.assertEqual(moltiplica(2, 3), 6)
        self.assertEqual(moltiplica(0, 5), 0)


if __name__ == "__main__":
    unittest.main()
