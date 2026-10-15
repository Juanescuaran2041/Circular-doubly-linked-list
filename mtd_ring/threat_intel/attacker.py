from dataclasses import dataclass


# An attacking IP address with the volume of reports other sensors have made about it.
@dataclass(frozen=True)
class Attacker:
    ip: str
    reports: int
    targets: int
