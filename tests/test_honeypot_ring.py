import unittest

from mtd_ring.errors import RingError
from mtd_ring.honeypot_ring import HoneypotRing


def ids(ring):
    return [node.id for node in ring]


class HoneypotRingTest(unittest.TestCase):
    def setUp(self):
        self.ring = HoneypotRing()

    def test_empty_ring(self):
        self.assertEqual(len(self.ring), 0)
        self.assertIsNone(self.ring.head)
        self.assertEqual(ids(self.ring), [])

    def test_single_node_points_to_itself(self):
        node = self.ring.append("A")
        self.assertIs(node.next, node)
        self.assertIs(node.prev, node)
        self.assertIs(self.ring.head, node)

    def test_append_keeps_insertion_order_and_circularity(self):
        a = self.ring.append("A")
        b = self.ring.append("B")
        c = self.ring.append("C")
        self.assertEqual(ids(self.ring), ["A", "B", "C"])
        self.assertIs(c.next, a)
        self.assertIs(a.prev, c)
        self.assertIs(a.next, b)
        self.assertIs(b.prev, a)

    def test_remove_head_moves_head(self):
        self.ring.append("A")
        b = self.ring.append("B")
        self.ring.append("C")
        self.ring.remove("A")
        self.assertIs(self.ring.head, b)
        self.assertEqual(ids(self.ring), ["B", "C"])

    def test_remove_middle_and_tail(self):
        for name in "ABCD":
            self.ring.append(name)
        self.ring.remove("B")
        self.ring.remove("D")
        self.assertEqual(ids(self.ring), ["A", "C"])
        a = self.ring.get("A")
        c = self.ring.get("C")
        self.assertIs(a.next, c)
        self.assertIs(c.next, a)
        self.assertIs(a.prev, c)

    def test_remove_only_node_then_append_again(self):
        self.ring.append("A")
        self.ring.remove("A")
        self.assertIsNone(self.ring.head)
        self.assertEqual(len(self.ring), 0)
        self.ring.append("B")
        self.assertEqual(ids(self.ring), ["B"])

    def test_duplicate_and_unknown_ids(self):
        self.ring.append("A")
        with self.assertRaises(RingError):
            self.ring.append("A")
        with self.assertRaises(RingError):
            self.ring.get("Z")
        with self.assertRaises(RingError):
            self.ring.remove("Z")

    def test_contains_and_clear(self):
        self.ring.append("A")
        self.assertIn("A", self.ring)
        self.assertNotIn("B", self.ring)
        self.ring.clear()
        self.assertEqual(len(self.ring), 0)
        self.assertIsNone(self.ring.head)

    def test_one_lap_iteration_terminates(self):
        for name in "ABC":
            self.ring.append(name)
        self.assertEqual(len(list(self.ring)), 3)


if __name__ == "__main__":
    unittest.main()
