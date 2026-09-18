from dataclasses import dataclass


@dataclass
class ROS2Adapter:
    name: str = "ros2"
    namespace: str = "/pulpo"

    def translate(self, command: str) -> str:
        return f"{self.namespace}/{command}"


__all__ = ["ROS2Adapter"]
