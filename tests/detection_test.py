import unittest
from stix2 import Detection,Identity,ObservedData
from stix2.base import NOW

class PriamTestCase(unittest.TestCase):
    def test_detection(self):
        detection = Detection(name="Suspicious logon")
        self.assertEqual(detection.name,"Suspicious logon")

        obs = ObservedData(number_observed=10,
                           first_observed="2023-01-01T08:00:01.000Z",
                           last_observed="2023-01-01T08:00:01.000Z",
                           object_refs=[detection])

        self.assertEqual(obs.object_refs, [detection.id])
    def test_identity(self):
        id1 = Identity(name="Company")
        id2 = Identity(name="Company")
        id3 = Identity(name="Another")
        self.assertEqual(id1.id,id2.id)
        self.assertNotEqual(id2.id,id3.id)

if __name__ == '__main__':
    unittest.main()
