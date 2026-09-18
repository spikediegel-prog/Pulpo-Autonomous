from ..base import PhysicalSystemDomain


class DronesDomain(PhysicalSystemDomain):
    def __init__(self, **kwargs):
        constraints = {
            "max_altitude_m": 120,
            "geofence": "default",
            "lost_link_timeout_s": 15,
        }
        constraints.update(kwargs.pop("constraints", {}))
        super().__init__(name="drones", constraints=constraints, **kwargs)

__all__ = ["DronesDomain"]
