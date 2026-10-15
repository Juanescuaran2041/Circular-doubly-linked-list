from __future__ import annotations

from typing import Iterator, Optional

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

    @property
    def head(self) -> Optional[HoneypotNode]:
        return self._head

    def __len__(self) -> int:
        return self._size

    def __contains__(self, honeypot_id: str) -> bool:
        raise NotImplementedError

    def __iter__(self) -> Iterator[HoneypotNode]:
        """Yield each node exactly once, starting at the head (one lap)."""
        raise NotImplementedError

    def append(self, honeypot_id: str) -> HoneypotNode:
        """Create a node and insert it before the head (tail). O(1).

        Raise ``RingError`` if the id already exists.
        """
        raise NotImplementedError

    def get(self, honeypot_id: str) -> HoneypotNode:
        """Return the node with that id in O(1). Raise ``RingError`` if unknown."""
        raise NotImplementedError

    def remove(self, honeypot_id: str) -> HoneypotNode:
        """Unlink the node by joining its neighbors. O(1).

        Update ``head`` if the removed node was the head. Return the removed node.
        Raise ``RingError`` if unknown.
        """
        raise NotImplementedError

    def clear(self) -> None:
        """Remove every node."""
        raise NotImplementedError
