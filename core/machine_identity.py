from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MachineIdentity:
    machine_id: str
    domain: str
    site: str
    key_fingerprint: str | None = None

    def scope_matches(self, required_domain: str | None = None, required_site: str | None = None) -> bool:
        if required_domain and self.domain != required_domain:
            return False
        if required_site and self.site != required_site:
            return False
        return True

    def describe(self) -> str:
        return f"{self.domain}:{self.site}:{self.machine_id}"
