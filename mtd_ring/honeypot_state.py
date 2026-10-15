from enum import Enum


class HoneypotState(str, Enum):
    EXPOSED = "EXPOSED"    # the only one visible to the network
    WAITING = "WAITING"    # in the ring, ready to be exposed
    ISOLATED = "ISOLATED"  # in quarantine, skipped by the rotation
