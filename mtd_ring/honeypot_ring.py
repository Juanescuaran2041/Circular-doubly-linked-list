from __future__ import annotations

from typing import Dict, Iterator, Optional

from mtd_ring.errors import RingError
from mtd_ring.honeypot_node import HoneypotNode


# Circular doubly linked list of honeypots, with an id index for O(1) lookups.
class HoneypotRing:

    def __init__(self) -> None:
        self._head: Optional[HoneypotNode] = None
        self._size: int = 0
        self._index: Dict[str, HoneypotNode] = {}

    @property
    def head(self) -> Optional[HoneypotNode]:
        return self._head

    def __len__(self) -> int:
        return self._size

    # Tells if a honeypot with that id is in the ring.
    def __contains__(self, honeypot_id: str) -> bool:
        return honeypot_id in self._index

    # Walks the ring one lap from the head, stopping after `size` steps.
    def __iter__(self) -> Iterator[HoneypotNode]:
        node = self._head
        for _ in range(self._size):
            yield node
            node = node.next

    # Adds a new honeypot at the tail (just before the head) in O(1).
    def append(self, honeypot_id: str) -> HoneypotNode:
        if honeypot_id in self._index:
            raise RingError(f"Duplicate honeypot id: {honeypot_id}")

        node = HoneypotNode(honeypot_id)

        if self._head is None:
            node.next = node
            node.prev = node
            self._head = node
        else:
            head = self._head
            tail = head.prev
            node.prev = tail
            node.next = head
            tail.next = node
            head.prev = node

        self._size += 1
        self._index[honeypot_id] = node
        return node

    # Finds a honeypot by id in O(1).
    def get(self, honeypot_id: str) -> HoneypotNode:
        node = self._index.get(honeypot_id)
        if node is None:
            raise RingError(f"Unknown honeypot: {honeypot_id}")
        return node

    # Unlinks a honeypot by joining its two neighbors in O(1).
    def remove(self, honeypot_id: str) -> HoneypotNode:
        node = self.get(honeypot_id)

        if self._size == 1:
            self._head = None
        else:
            before = node.prev
            after = node.next
            before.next = after
            after.prev = before
            if node is self._head:
                self._head = after

        node.next = None
        node.prev = None
        self._size -= 1
        del self._index[honeypot_id]
        return node

    # Empties the ring and its index.
    def clear(self) -> None:
        for node in list(self):
            node.next = None
            node.prev = None
        self._head = None
        self._size = 0
        self._index.clear()
