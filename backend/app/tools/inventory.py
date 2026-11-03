"""get_host_info, get_user_info and check_reputation: lookups in the asset list, the
directory and the local threat-intel feed. No event rows, so no event_ids here."""

import ipaddress
import re
from typing import Annotated, Any, Literal, Self

from pydantic import Field, StringConstraints, model_validator
from pymongo.asynchronous.database import AsyncDatabase

from app.tools._common import ToolError, ToolInput, UserName

DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
HOSTNAME = re.compile(r"^[A-Z0-9][A-Z0-9-]{0,31}$")


class HostInfoInput(ToolInput):
    host: Annotated[str, StringConstraints(max_length=39)] = Field(
        description="Hostname like FIN-WS-01, or an internal IP like 10.20.1.12."
    )


async def get_host_info(params: HostInfoInput, db: AsyncDatabase) -> dict[str, Any]:
    value = params.host
    try:
        query = {"ip": str(ipaddress.ip_address(value))}
    except ValueError:
        if not HOSTNAME.match(value.upper()):
            raise ToolError(f"{value!r} is neither a hostname nor an IP address") from None
        query = {"hostname": value.upper()}
    doc = await db.hosts.find_one(query, {"_id": 0})
    if doc is None:
        raise ToolError(f"no host matches {value}; it may be outside the asset inventory")
    return {"untrusted_log_data": doc}


class UserInfoInput(ToolInput):
    user: UserName = Field(description="Account name, e.g. priya.n or svc_backup.")


async def get_user_info(params: UserInfoInput, db: AsyncDatabase) -> dict[str, Any]:
    doc = await db.users.find_one({"username": params.user}, {"_id": 0})
    if doc is None:
        raise ToolError(f"no account {params.user} in the directory")
    return {"untrusted_log_data": doc}


class ReputationInput(ToolInput):
    indicator: Annotated[str, StringConstraints(min_length=1, max_length=253, to_lower=True)]
    type: Literal["ip", "domain", "hash"] = Field(description="ip, domain, or hash (SHA-256).")

    @model_validator(mode="after")
    def _well_formed(self) -> Self:
        if self.type == "ip":
            try:
                ipaddress.ip_address(self.indicator)
            except ValueError:
                raise ValueError(f"{self.indicator!r} is not an IP address") from None
        elif self.type == "domain" and not DOMAIN.match(self.indicator):
            raise ValueError(f"{self.indicator!r} is not a domain name")
        elif self.type == "hash" and not SHA256.match(self.indicator):
            raise ValueError("hash must be a 64-character hex SHA-256")
        return self


async def check_reputation(params: ReputationInput, db: AsyncDatabase) -> dict[str, Any]:
    doc = await db.intel.find_one({"indicator": params.indicator, "type": params.type}, {"_id": 0})
    if doc is None:
        doc = {"indicator": params.indicator, "type": params.type, "reputation": "unknown"}
    return {"untrusted_log_data": doc}
