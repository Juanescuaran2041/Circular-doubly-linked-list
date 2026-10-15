import copy
import random
import unittest

from mtd_ring.config import RingConfig
from mtd_ring.errors import InvalidSessionError, RingError
from mtd_ring.mtd_controller import MTDController
from mtd_ring.simulation.threat_simulator import ThreatSimulator
from mtd_ring.threat_intel.attacker import Attacker


class FakeFeed:
    source = "fake"
    status = ("live", 1)

    def attackers(self):
        return [Attacker("203.0.113.9", 100, 1)]


def busy_controller():
    controller = MTDController(RingConfig(initial_size=4))
    controller.register_attack("HP-2")
    controller.rotate()
    controller.isolate("HP-4")
    controller.advance_time(31_000)
    return controller


class ControllerStateTest(unittest.TestCase):
    def test_a_restored_controller_has_the_same_snapshot_and_state(self):
        original = busy_controller()
        exported = original.export_state()
        restored = MTDController(RingConfig(initial_size=4))
        restored.restore_state(exported)
        self.assertEqual(restored.snapshot(), original.snapshot())
        self.assertEqual(restored.export_state(), exported)

    def test_a_restored_controller_keeps_behaving_like_the_original(self):
        original = busy_controller()
        restored = MTDController(RingConfig(initial_size=4))
        restored.restore_state(original.export_state())
        for controller in (original, restored):
            controller.add_honeypot()
            controller.rotate(-1)
            controller.advance_time(70_000)
        self.assertEqual(restored.snapshot(), original.snapshot())

    def test_restoring_an_empty_ring_works(self):
        controller = MTDController(RingConfig(initial_size=1))
        controller.remove("HP-1")
        restored = MTDController(RingConfig(initial_size=3))
        restored.restore_state(controller.export_state())
        self.assertEqual(restored.snapshot()["honeypots"], [])
        self.assertIsNone(restored.snapshot()["exposed_id"])

    def test_the_exported_state_is_plain_json_data(self):
        import json

        exported = busy_controller().export_state()
        self.assertEqual(json.loads(json.dumps(exported)), exported)

    def test_rejects_malformed_controller_states(self):
        valid = busy_controller().export_state()
        breakers = {
            "not an object": lambda s: "oops",
            "missing honeypots": lambda s: s.pop("honeypots"),
            "honeypots not a list": lambda s: s.update(honeypots={}),
            "too many honeypots": lambda s: s.update(honeypots=[s["honeypots"][0]] * 500),
            "duplicate ids": lambda s: s["honeypots"].append(dict(s["honeypots"][0])),
            "bad id characters": lambda s: s["honeypots"][0].update(id="<script>"),
            "id too long": lambda s: s["honeypots"][0].update(id="A" * 33),
            "unknown state": lambda s: s["honeypots"][0].update(state="HACKED"),
            "negative attacks": lambda s: s["honeypots"][0].update(attacks=-1),
            "boolean as number": lambda s: s.update(now=True),
            "string as number": lambda s: s.update(now="5"),
            "huge number": lambda s: s.update(now=10**30),
            "unknown exposed": lambda s: s.update(exposed="HP-99"),
            "isolated without end": lambda s: s["honeypots"][0].update(state="ISOLATED", quarantine_ends_at=None),
            "quarantine end without isolation": lambda s: s["honeypots"][0].update(state="WAITING", quarantine_ends_at=5),
            "long history": lambda s: s.update(history=["HP-1"] * 500),
        }
        for name, break_it in breakers.items():
            state = copy.deepcopy(valid)
            replacement = break_it(state)
            if name == "not an object":
                state = replacement
            controller = MTDController(RingConfig(initial_size=2))
            with self.assertRaises(InvalidSessionError, msg=name):
                controller.restore_state(state)

    def test_a_rejected_state_leaves_the_controller_untouched(self):
        controller = MTDController(RingConfig(initial_size=3))
        before = controller.export_state()
        with self.assertRaises(RingError):
            controller.restore_state({"honeypots": "nope"})
        self.assertEqual(controller.export_state(), before)

    def test_more_than_one_exposed_honeypot_is_rejected(self):
        state = MTDController(RingConfig(initial_size=3)).export_state()
        state["honeypots"][1]["state"] = "EXPOSED"
        with self.assertRaises(InvalidSessionError):
            MTDController(RingConfig(initial_size=3)).restore_state(state)


class ThreatStateTest(unittest.TestCase):
    def make(self):
        controller = MTDController(RingConfig(initial_size=4, attack_threshold=100))
        simulator = ThreatSimulator(controller, FakeFeed(), rng=random.Random(3), attack_chance=1.0, stale_chance=0.5)
        return controller, simulator

    def test_a_restored_simulator_has_the_same_snapshot(self):
        controller, simulator = self.make()
        simulator.enable()
        simulator.advance(6000)
        exported = simulator.export_state()
        _, restored = self.make()
        restored.restore_state(exported)
        self.assertEqual(restored.snapshot(), simulator.snapshot())
        self.assertTrue(restored.enabled)

    def test_event_ids_keep_increasing_after_a_restore(self):
        controller, simulator = self.make()
        simulator.enable()
        simulator.advance(3000)
        last = simulator.snapshot()["events"][-1]["id"]
        controller2, restored = self.make()
        restored.restore_state(simulator.export_state())
        restored.advance(2000)
        self.assertGreater(restored.snapshot()["events"][-1]["id"], last)

    def test_rejects_malformed_simulator_states(self):
        _, simulator = self.make()
        simulator.enable()
        simulator.advance(2000)
        valid = simulator.export_state()
        breakers = {
            "enabled not boolean": lambda s: s.update(enabled="yes"),
            "next_id zero": lambda s: s.update(next_id=0),
            "negative landed": lambda s: s.update(landed=-1),
            "too many events": lambda s: s.update(events=[s["events"][0]] * 100),
            "bad ip": lambda s: s["events"][0].update(ip="not-an-ip"),
            "markup in ip": lambda s: s["events"][0].update(ip="<img src=x>"),
            "bad outcome": lambda s: s["events"][0].update(outcome="exploded"),
            "bad target": lambda s: s["events"][0].update(target="../../etc"),
            "event not an object": lambda s: s.update(events=[1]),
        }
        for name, break_it in breakers.items():
            state = copy.deepcopy(valid)
            break_it(state)
            _, target = self.make()
            with self.assertRaises(InvalidSessionError, msg=name):
                target.restore_state(state)


if __name__ == "__main__":
    unittest.main()
