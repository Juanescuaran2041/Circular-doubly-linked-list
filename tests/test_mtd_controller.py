import unittest

from mtd_ring.config import RingConfig
from mtd_ring.errors import RingError
from mtd_ring.mtd_controller import MTDController


def make_controller(size=3):
    return MTDController(RingConfig(initial_size=size))


def states(controller):
    return {h["id"]: h["state"] for h in controller.snapshot()["honeypots"]}


class MTDControllerTest(unittest.TestCase):
    def test_initial_state_has_one_exposed(self):
        controller = make_controller(3)
        snapshot = controller.snapshot()
        self.assertEqual(len(snapshot["honeypots"]), 3)
        self.assertEqual(list(states(controller).values()).count("EXPOSED"), 1)
        self.assertEqual(snapshot["exposed_id"], snapshot["honeypots"][0]["id"])

    def test_full_rotation_cycle_returns_to_start(self):
        controller = make_controller(3)
        start = controller.snapshot()["exposed_id"]
        seen = []
        for _ in range(3):
            controller.rotate()
            seen.append(controller.snapshot()["exposed_id"])
        self.assertEqual(seen[-1], start)
        self.assertEqual(len(set(seen)), 3)

    def test_rotate_backward_wraps_around(self):
        controller = make_controller(3)
        first = controller.snapshot()["exposed_id"]
        controller.rotate(-1)
        last = controller.snapshot()["honeypots"][-1]["id"]
        self.assertEqual(controller.snapshot()["exposed_id"], last)
        controller.rotate(1)
        self.assertEqual(controller.snapshot()["exposed_id"], first)

    def test_invalid_direction_and_unknown_id(self):
        controller = make_controller()
        with self.assertRaises(RingError):
            controller.rotate(0)
        with self.assertRaises(RingError):
            controller.register_attack("nope")

    def test_attack_on_exposed_rotates_immediately(self):
        controller = make_controller(3)
        exposed = controller.snapshot()["exposed_id"]
        controller.register_attack(exposed)
        self.assertNotEqual(controller.snapshot()["exposed_id"], exposed)

    def test_attack_on_waiting_does_not_rotate(self):
        controller = make_controller(3)
        exposed = controller.snapshot()["exposed_id"]
        waiting = next(i for i, s in states(controller).items() if s == "WAITING")
        controller.register_attack(waiting)
        self.assertEqual(controller.snapshot()["exposed_id"], exposed)

    def test_threshold_isolates_and_rotation_skips_it(self):
        config = RingConfig(initial_size=3, attack_threshold=2)
        controller = MTDController(config)
        target = next(i for i, s in states(controller).items() if s == "WAITING")
        controller.register_attack(target)
        controller.register_attack(target)
        self.assertEqual(states(controller)[target], "ISOLATED")
        for _ in range(4):
            controller.rotate()
            self.assertNotEqual(controller.snapshot()["exposed_id"], target)

    def test_quarantine_ends_after_configured_time(self):
        controller = make_controller(3)
        target = next(i for i, s in states(controller).items() if s == "WAITING")
        controller.isolate(target)
        controller.advance_time(controller.snapshot()["config"]["quarantine_ms"])
        self.assertEqual(states(controller)[target], "WAITING")

    def test_all_isolated_does_not_loop_forever_and_recovers(self):
        controller = make_controller(3)
        for honeypot_id in list(states(controller)):
            controller.isolate(honeypot_id)
        controller.rotate()  # must return
        controller.advance_time(controller.snapshot()["config"]["quarantine_ms"])
        self.assertIn("EXPOSED", states(controller).values())

    def test_automatic_rotation_after_interval(self):
        controller = make_controller(3)
        first = controller.snapshot()["exposed_id"]
        controller.advance_time(controller.snapshot()["config"]["rotation_interval_ms"])
        self.assertNotEqual(controller.snapshot()["exposed_id"], first)

    def test_remove_exposed_rotates_first(self):
        controller = make_controller(3)
        exposed = controller.snapshot()["exposed_id"]
        controller.remove(exposed)
        snapshot = controller.snapshot()
        self.assertEqual(len(snapshot["honeypots"]), 2)
        self.assertNotEqual(snapshot["exposed_id"], exposed)

    def test_remove_all_then_add(self):
        controller = make_controller(1)
        only = controller.snapshot()["exposed_id"]
        controller.remove(only)
        self.assertIsNone(controller.snapshot()["exposed_id"])
        new_id = controller.add_honeypot()
        self.assertEqual(controller.snapshot()["exposed_id"], new_id)

    def test_reset_restores_initial_size(self):
        controller = make_controller(3)
        controller.add_honeypot()
        controller.reset()
        self.assertEqual(len(controller.snapshot()["honeypots"]), 3)


if __name__ == "__main__":
    unittest.main()
