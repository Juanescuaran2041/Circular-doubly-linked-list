from enum import Enum


# The three situations a honeypot can be in.
class HoneypotState(str, Enum):
    EXPOSED = "EXPOSED"
    WAITING = "WAITING"
    ISOLATED = "ISOLATED"
