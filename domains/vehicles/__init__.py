from ..base import PhysicalSystemDomain


class VehiclesDomain(PhysicalSystemDomain):
    def __init__(self, **kwargs):
        constraints = {
            "route_budget": 50,
            "speed_limit": 30,
            "occupancy_guard": True,
        }
        constraints.update(kwargs.pop("constraints", {}))
        super().__init__(name="vehicles", constraints=constraints, **kwargs)

__all__ = ["VehiclesDomain"]
