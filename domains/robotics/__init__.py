from ..base import PhysicalSystemDomain


class RoboticsDomain(PhysicalSystemDomain):
    def __init__(self, **kwargs):
        constraints = {
            "safety_margin": 1.0,
            "operator_override": False,
            "task_budget": 100,
        }
        constraints.update(kwargs.pop("constraints", {}))
        super().__init__(name="robotics", constraints=constraints, **kwargs)

__all__ = ["RoboticsDomain"]
