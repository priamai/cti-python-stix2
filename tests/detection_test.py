import unittest
from stix2 import Detection,Identity

class PriamTestCase(unittest.TestCase):
    def test_detection(self):
        detection = Detection(name="Suspicious logon")
        self.assertEqual(detection.name,"Suspicious logon")  # add assertion here

    def test_identity(self):
        id1 = Identity(name="Company")
        id2 = Identity(name="Company")
        self.assertEqual(id1.id,id2.id)  # add assertion here

if __name__ == '__main__':
    unittest.main()
