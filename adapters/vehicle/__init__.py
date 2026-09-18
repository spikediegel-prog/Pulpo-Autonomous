from dataclasses import dataclass


@dataclass
class VehicleAdapter:
    name: str = "vehicle"
    route_policy: str = "safe"

    def translate(self, command: str) -> str:
        return f"vehicle:{self.route_policy}:{command}"


__all__ = ["VehicleAdapter"]
