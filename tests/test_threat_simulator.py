import random
import unittest

from mtd_ring.config import RingConfig
from mtd_ring.errors import NegativeTimeError
from mtd_ring.mtd_controller import MTDController
from mtd_ring.simulation.threat_simulator import ThreatSimulator
from mtd_ring.threat_intel.attacker import Attacker


class FakeFeed:
    source = "fake feed"

    def attackers(self):
        return [Attacker("203.0.113.9", 100, 1)]


def make(attack_chance=1.0, stale_chance=0.0, **config):
    controller = MTDController(RingConfig(initial_size=4, rotation_interval_ms=10_000_000, **config))
    simulator = ThreatSimulator(
        controller, FakeFeed(), rng=random.Random(1), attack_chance=attack_chance, stale_chance=stale_chance
    )
    return controller, simulator


class ThreatSimulatorTest(unittest.TestCase):
    def test_disabled_simulator_only_advances_the_clock(self):
        controller, simulator = make()
        simulator.advance(5000)
        self.assertEqual(controller.snapshot()["now_ms"], 5000)
        self.assertEqual(simulator.snapshot()["events"], [])

    def test_enabled_simulator_attacks_once_per_second(self):
        controller, simulator = make(attack_chance=1.0, attack_threshold=100)
        simulator.enable()
        simulator.advance(3000)
        snapshot = simulator.snapshot()
        self.assertEqual(controller.snapshot()["now_ms"], 3000)
        self.assertEqual(snapshot["landed"], 3)
        self.assertEqual([e["outcome"] for e in snapshot["events"]], ["landed"] * 3)
        self.assertEqual({e["ip"] for e in snapshot["events"]}, {"203.0.113.9"})

    def test_partial_seconds_do_not_trigger_attacks(self):
        _, simulator = make(attack_chance=1.0)
        simulator.enable()
        simulator.advance(900)
        self.assertEqual(simulator.snapshot()["events"], [])

    def test_landed_attack_is_counted_by_the_controller(self):
        controller, simulator = make(attack_chance=1.0, attack_threshold=100)
        simulator.enable()
        simulator.advance(2000)
        total = sum(n["attacks"] for n in controller.snapshot()["honeypots"])
        self.assertEqual(total, 2)

    def test_attacks_on_a_rotated_away_server_are_missed_and_not_counted(self):
        controller, simulator = make(attack_chance=1.0, stale_chance=1.0)
        first = controller.snapshot()["exposed_id"]
        controller.rotate()
        simulator.enable()
        simulator.advance(2000)
        snapshot = simulator.snapshot()
        self.assertEqual(snapshot["missed"], 2)
        self.assertEqual(snapshot["landed"], 0)
        self.assertEqual({e["target"] for e in snapshot["events"]}, {first})
        self.assertTrue(all(n["attacks"] == 0 for n in controller.snapshot()["honeypots"]))

    def test_repeated_attacks_trigger_the_isolation_threshold(self):
        controller, simulator = make(attack_chance=1.0, attack_threshold=3)
        simulator.enable()
        simulator.advance(10_000)
        states = [n["state"] for n in controller.snapshot()["honeypots"]]
        self.assertIn("ISOLATED", states)

    def test_negative_time_is_still_rejected(self):
        _, simulator = make()
        simulator.enable()
        with self.assertRaises(NegativeTimeError):
            simulator.advance(-1)

    def test_clear_forgets_events_and_totals(self):
        _, simulator = make(attack_chance=1.0)
        simulator.enable()
        simulator.advance(2000)
        simulator.clear()
        snapshot = simulator.snapshot()
        self.assertEqual((snapshot["events"], snapshot["landed"], snapshot["missed"]), ([], 0, 0))
        self.assertTrue(snapshot["enabled"])

    def test_disable_stops_new_attacks(self):
        _, simulator = make(attack_chance=1.0)
        simulator.enable()
        simulator.disable()
        simulator.advance(3000)
        self.assertEqual(simulator.snapshot()["events"], [])


if __name__ == "__main__":
    unittest.main()
