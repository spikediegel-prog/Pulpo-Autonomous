from dataclasses import dataclass


@dataclass
class MAVLinkAdapter:
    name: str = "mavlink"
    system_id: int = 1

    def translate(self, command: str) -> str:
        return f"mavlink:{self.system_id}:{command}"


__all__ = ["MAVLinkAdapter"]
