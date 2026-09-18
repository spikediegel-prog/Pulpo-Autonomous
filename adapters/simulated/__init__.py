from dataclasses import dataclass


@dataclass
class SimulatedAdapter:
    name: str = "simulated"
    environment: str = "local"

    def translate(self, command: str) -> str:
        return f"sim:{command}"


__all__ = ["SimulatedAdapter"]
