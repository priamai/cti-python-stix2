import unittest
from stix2 import Detection,Identity,ObservedData,Alert,Asset,IPv4Address
from stix2.v21.vocab import ALERT_CONTEXT,ALERT_CONTEXT_RULE
from stix2.base import NOW

class PriamTestCase(unittest.TestCase):
    def test_detection(self):
        detection = Detection(name="Suspicious logon",
                              engine="SIGMA",
                              severity_score=1,
                              fp_counts=1,tp_counts=9,
                              labels=["SIEM"])

        self.assertEqual(detection.name,"Suspicious logon")

        obs = ObservedData(number_observed=10,
                           first_observed="2023-01-01T08:00:01.000Z",
                           last_observed="2023-01-01T08:00:01.000Z",
                           object_refs=[detection])

        self.assertEqual(obs.object_refs, [detection.id])

    def test_asset(self):
        siem_host = IPv4Address(value="10.0.0.1")

        asset = Asset(value="computer.contoso.org",labels=["a","b","c"],resolves_to_refs=[siem_host])

        self.assertEqual(asset.value,"computer.contoso.org")

    def test_identity(self):
        id1 = Identity(name="Company")
        id2 = Identity(name="Company")
        id3 = Identity(name="Another")
        self.assertEqual(id1.id,id2.id)
        self.assertNotEqual(id2.id,id3.id)

    def test_alert(self):
        siem_host = Identity(name="McAfee 12.4",
                             identity_class="system",
                             roles=["SIEM"],
                             labels=["SIEM"],
                             confidence=90,  # from 0 to 100
                             external_references=[],
                             contact_information="10.0.0.1")

        detection = Detection(name="Suspicious logon",
                              engine="SIGMA",
                              severity_score=10,
                              fp_counts=1,tp_counts=9,
                              labels=["SIEM"])

        alert = Alert(name="alert 1",
                      created_by_ref = siem_host,
                      context=ALERT_CONTEXT_RULE,
                      ranking_score=0.1,
                      object_refs=[detection])

        obs = ObservedData(number_observed=10,
                           first_observed="2023-01-01T08:00:01.000Z",
                           last_observed="2023-01-01T08:00:01.000Z",
                           object_refs=[detection,alert])

if __name__ == '__main__':
    unittest.main()
