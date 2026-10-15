import http.client
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


def run_inline(task):
    task()


def make_feed(fetch_json, **options):
    return SansIscFeed(fetch_json=fetch_json, spawn=run_inline, **options)


def failing(error):
    def fetch(url):
        raise error

    return fetch


class SansIscFeedTest(unittest.TestCase):
    def test_parses_a_list_of_records(self):
        feed = make_feed(lambda url: SAMPLE)
        attackers = feed.attackers()
        self.assertEqual([a.ip for a in attackers], ["13.94.254.200", "194.224.249.214"])
        self.assertEqual(attackers[0].reports, 319739)
        self.assertIn("SANS ISC DShield", feed.source)

    def test_reports_that_nothing_is_loaded_before_the_first_request(self):
        feed = make_feed(lambda url: SAMPLE)
        self.assertIn("not loaded yet", feed.source)

    def test_status_goes_from_pending_to_live_or_offline(self):
        live = make_feed(lambda url: SAMPLE)
        self.assertEqual(live.status, ("pending", 0))
        live.attackers()
        self.assertEqual(live.status, ("live", 2))

        offline = make_feed(failing(OSError("no network")))
        offline.attackers()
        self.assertEqual(offline.status, ("offline", len(OFFLINE_SAMPLE)))

    def test_does_not_block_while_the_download_is_pending(self):
        pending = []
        feed = SansIscFeed(fetch_json=lambda url: SAMPLE, spawn=pending.append)

        self.assertEqual(feed.attackers(), [])
        self.assertEqual(feed.status, ("loading", 0))
        self.assertIn("loading", feed.source)
        self.assertEqual(len(pending), 1)

        feed.attackers()
        self.assertEqual(len(pending), 1, "a second call must not start another download")

        pending[0]()
        self.assertEqual(feed.status, ("live", 2))
        self.assertEqual(len(feed.attackers()), 2)

    def test_parses_a_dictionary_keyed_by_position(self):
        feed = make_feed(lambda url: {"0": SAMPLE[0], "1": SAMPLE[1], "date": "2026-10-15"})
        self.assertEqual(len(feed.attackers()), 2)

    def test_normalizes_padded_ips_and_skips_invalid_ones(self):
        payload = [
            {"source": "013.094.254.200", "reports": 5, "targets": 1},
            {"source": "not-an-ip", "reports": 9, "targets": 1},
            {"source": "999.1.1.1", "reports": 9, "targets": 1},
            {"reports": 9},
        ]
        attackers = make_feed(lambda url: payload).attackers()
        self.assertEqual([a.ip for a in attackers], ["13.94.254.200"])

    def test_falls_back_to_the_offline_sample_when_the_request_fails(self):
        feed = make_feed(failing(OSError("no network")))
        self.assertEqual(feed.attackers(), OFFLINE_SAMPLE)
        self.assertIn("Offline sample", feed.source)

    def test_any_kind_of_failure_falls_back_instead_of_crashing(self):
        errors = [
            http.client.IncompleteRead(b"partial"),
            http.client.RemoteDisconnected("closed"),
            ValueError("bad json"),
            RuntimeError("anything else"),
        ]
        for error in errors:
            feed = make_feed(failing(error))
            self.assertEqual(feed.attackers(), OFFLINE_SAMPLE, repr(error))

    def test_falls_back_when_the_response_is_empty_or_malformed(self):
        self.assertEqual(make_feed(lambda url: []).attackers(), OFFLINE_SAMPLE)
        self.assertEqual(make_feed(lambda url: "oops").attackers(), OFFLINE_SAMPLE)

    def test_caches_until_the_ttl_expires(self):
        calls = []
        clock = FakeClock()

        def fetch(url):
            calls.append(url)
            return SAMPLE

        feed = make_feed(fetch, ttl_seconds=100, clock=clock)
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

        feed = make_feed(fetch, ttl_seconds=10, clock=clock)
        feed.attackers()
        clock.now = 11
        attackers = feed.attackers()
        self.assertEqual(len(attackers), 2)
        self.assertIn("SANS ISC DShield", feed.source)


if __name__ == "__main__":
    unittest.main()
