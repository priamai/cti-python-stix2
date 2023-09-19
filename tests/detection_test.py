import unittest
from stix2 import Detection

class MyTestCase(unittest.TestCase):
    def test_detection(self):
        detection = Detection(name="Suspicious logon")
        self.assertEqual(True, False)  # add assertion here


if __name__ == '__main__':
    unittest.main()
