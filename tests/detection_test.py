import unittest
from stix2 import Detection

class PriamTestCase(unittest.TestCase):
    def test_detection(self):
        detection = Detection(name="Suspicious logon")
        self.assertEqual(detection.name,"Suspicious logon")  # add assertion here


if __name__ == '__main__':
    unittest.main()
