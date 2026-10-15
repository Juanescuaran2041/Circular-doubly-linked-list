from dataclasses import dataclass


# Tunable parameters of the defense; durations are in milliseconds.
@dataclass(frozen=True)
class RingConfig:
    rotation_interval_ms: int = 30_000
    attack_threshold: int = 3
    quarantine_ms: int = 60_000
    initial_size: int = 5
    history_limit: int = 12
