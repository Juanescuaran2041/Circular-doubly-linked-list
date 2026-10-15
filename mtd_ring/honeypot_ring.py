from __future__ import annotations

from typing import Dict, Iterator, Optional

from mtd_ring.errors import RingError
from mtd_ring.honeypot_node import HoneypotNode


class HoneypotRing:
    """Circular doubly linked list of ``HoneypotNode``.

    Pure structure: it knows nothing about rotation policy, time or attacks.

    Invariants (to be kept by every operation):
      * Empty ring: ``head is None`` and ``len == 0``.
      * Single node: ``node.next is node`` and ``node.prev is node``.
      * Otherwise ``head.prev`` is the tail and ``tail.next`` is ``head``.

    Suggested internal state: ``_head``, ``_size`` and a ``dict[str, HoneypotNode]``
    index so ``get`` and ``remove`` need no traversal.
    """

    def __init__(self) -> None:
        self._head: Optional[HoneypotNode] = None
        self._size: int = 0
        # id -> node. It lets get() and remove() find a node without walking the ring.
        self._index: Dict[str, HoneypotNode] = {}

    @property
    def head(self) -> Optional[HoneypotNode]:
        return self._head

    def __len__(self) -> int:
        return self._size

    def __contains__(self, honeypot_id: str) -> bool:
        return honeypot_id in self._index

    def __iter__(self) -> Iterator[HoneypotNode]:
        """Yield each node exactly once, starting at the head (one lap)."""
        node = self._head
        # A circular list never reaches None, so we stop after `size` steps instead.
        # Looping "until node is None" would run forever.
        for _ in range(self._size):
            yield node
            node = node.next

    def append(self, honeypot_id: str) -> HoneypotNode:
        """Create a node and insert it before the head (tail). O(1).

        Raise ``RingError`` if the id already exists.
        """
        if honeypot_id in self._index:
            raise RingError(f"Duplicate honeypot id: {honeypot_id}")

        node = HoneypotNode(honeypot_id)

        if self._head is None:
            # First node: it is both head and tail, so it points to itself both ways.
            node.next = node
            node.prev = node
            self._head = node
        else:
            # "Before the head" in a circle is the same place as "after the tail".
            head = self._head
            tail = head.prev
            # 1) Point the new node at its two future neighbors...
            node.prev = tail
            node.next = head
            # 2) ...then make those neighbors point back at it.
            tail.next = node
            head.prev = node

        self._size += 1
        self._index[honeypot_id] = node
        return node

    def get(self, honeypot_id: str) -> HoneypotNode:
        """Return the node with that id in O(1). Raise ``RingError`` if unknown."""
        node = self._index.get(honeypot_id)
        if node is None:
            raise RingError(f"Unknown honeypot: {honeypot_id}")
        return node

    def remove(self, honeypot_id: str) -> HoneypotNode:
        """Unlink the node by joining its neighbors. O(1).

        Update ``head`` if the removed node was the head. Return the removed node.
        Raise ``RingError`` if unknown.
        """
        node = self.get(honeypot_id)

        if self._size == 1:
            # The only node: nothing left to link, the ring becomes empty.
            self._head = None
        else:
            # Join the two neighbors to each other, skipping `node`:
            #   before <-> node <-> after   becomes   before <-> after
            before = node.prev
            after = node.next
            before.next = after
            after.prev = before
            # If we removed the head, the next node takes over as head.
            if node is self._head:
                self._head = after

        # Cut the removed node's own links so it no longer points into the ring.
        node.next = None
        node.prev = None
        self._size -= 1
        del self._index[honeypot_id]
        return node

    def clear(self) -> None:
        """Remove every node."""
        raise NotImplementedError
