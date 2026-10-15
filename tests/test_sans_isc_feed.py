import unittest

from mtd_ring.threat_intel.sans_isc_feed import OFFLINE_SAMPLE, SansIscFeed

SAMPLE = [
    {"rank": 1, "source": "13.94.254.200", "reports": 319739, "targets": 1},
    {"rank": 2, "source": "194.224.249.214", "reports": 309508, "targets": 2},
]


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class SansIscFeedTest(unittest.TestCase):
    def test_parses_a_list_of_records(self):
        feed = SansIscFeed(fetch_json=lambda url: SAMPLE)
        attackers = feed.attackers()
        self.assertEqual([a.ip for a in attackers], ["13.94.254.200", "194.224.249.214"])
        self.assertEqual(attackers[0].reports, 319739)
        self.assertIn("SANS ISC DShield", feed.source)

    def test_parses_a_dictionary_keyed_by_position(self):
        feed = SansIscFeed(fetch_json=lambda url: {"0": SAMPLE[0], "1": SAMPLE[1], "date": "2026-10-15"})
        self.assertEqual(len(feed.attackers()), 2)

    def test_normalizes_padded_ips_and_skips_invalid_ones(self):
        payload = [
            {"source": "013.094.254.200", "reports": 5, "targets": 1},
            {"source": "not-an-ip", "reports": 9, "targets": 1},
            {"source": "999.1.1.1", "reports": 9, "targets": 1},
            {"reports": 9},
        ]
        attackers = SansIscFeed(fetch_json=lambda url: payload).attackers()
        self.assertEqual([a.ip for a in attackers], ["13.94.254.200"])

    def test_falls_back_to_the_offline_sample_when_the_request_fails(self):
        def failing(url):
            raise OSError("no network")

        feed = SansIscFeed(fetch_json=failing)
        self.assertEqual(feed.attackers(), OFFLINE_SAMPLE)
        self.assertIn("Offline sample", feed.source)

    def test_falls_back_when_the_response_is_empty_or_malformed(self):
        self.assertEqual(SansIscFeed(fetch_json=lambda url: []).attackers(), OFFLINE_SAMPLE)
        self.assertEqual(SansIscFeed(fetch_json=lambda url: "oops").attackers(), OFFLINE_SAMPLE)

    def test_caches_until_the_ttl_expires(self):
        calls = []
        clock = FakeClock()

        def fetch(url):
            calls.append(url)
            return SAMPLE

        feed = SansIscFeed(ttl_seconds=100, fetch_json=fetch, clock=clock)
        feed.attackers()
        clock.now = 99
        feed.attackers()
        self.assertEqual(len(calls), 1)
        clock.now = 101
        feed.attackers()
        self.assertEqual(len(calls), 2)

    def test_keeps_the_last_live_list_when_a_refresh_fails(self):
        clock = FakeClock()
        responses = [SAMPLE, OSError("down")]

        def fetch(url):
            response = responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

        feed = SansIscFeed(ttl_seconds=10, fetch_json=fetch, clock=clock)
        feed.attackers()
        clock.now = 11
        attackers = feed.attackers()
        self.assertEqual(len(attackers), 2)
        self.assertIn("SANS ISC DShield", feed.source)


if __name__ == "__main__":
    unittest.main()
