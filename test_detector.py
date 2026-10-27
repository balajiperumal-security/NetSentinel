import unittest
from detector import analyze_event
from response_engine import recommend_response

class DetectorTests(unittest.TestCase):
    def test_normal_event_is_low(self):
        e = analyze_event({'source_ip':'192.0.2.10','event_type':'normal_connection','failed_attempts':0,'destination_port':443,'bytes_sent':1000})
        self.assertEqual(e['risk_level'], 'Low')
        self.assertGreaterEqual(e['risk_score'], 0)

    def test_brute_force_high_risk(self):
        e = analyze_event({'source_ip':'192.0.2.11','event_type':'brute_force','failed_attempts':14,'destination_port':22,'bytes_sent':10})
        self.assertEqual(e['risk_level'], 'High')
        self.assertIn('failed attempts', e['explanation'])

    def test_large_outbound_transfer_is_flagged(self):
        e = analyze_event({'event_type':'unusual_outbound','failed_attempts':0,'destination_port':443,'bytes_sent':6000000})
        self.assertIn(e['risk_level'], ('Medium','High'))
        self.assertIn('5 MB', e['explanation'])

    def test_score_is_capped(self):
        e = analyze_event({'event_type':'brute_force','failed_attempts':100,'destination_port':22,'bytes_sent':9000000})
        self.assertEqual(e['risk_score'], 100)

    def test_high_risk_response_is_advisory(self):
        e = analyze_event({'event_type':'brute_force','failed_attempts':12,'destination_port':22})
        steps = recommend_response(e)
        self.assertTrue(steps)
        self.assertTrue(any('approval' in s.lower() or 'runbook' in s.lower() for s in steps))

if __name__ == '__main__': unittest.main()
