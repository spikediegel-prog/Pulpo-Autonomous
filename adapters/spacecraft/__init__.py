from dataclasses import dataclass


@dataclass
class SpacecraftAdapter:
    name: str = "spacecraft"
    command_window_s: int = 120

    def translate(self, command: str) -> str:
        return f"spacecraft:{self.command_window_s}:{command}"


__all__ = ["SpacecraftAdapter"]
