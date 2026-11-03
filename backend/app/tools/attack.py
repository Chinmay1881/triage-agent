"""search_attack_techniques and lookup_attack_technique, backed by the pinned v20 bundle.

These answer from MITRE's data, not from logs, so results go under "attack_catalog"
instead of "untrusted_log_data"."""

from typing import Annotated, Any

from pydantic import Field, StringConstraints
from pymongo.asynchronous.database import AsyncDatabase

from app.attack.catalog import get_catalog
from app.tools._common import ToolError, ToolInput

SEARCH_LIMIT = 5


class TechniqueSearchInput(ToolInput):
    keyword: Annotated[str, StringConstraints(min_length=2, max_length=60)] = Field(
        description="Words to look for in technique names and descriptions, e.g. 'lsass'."
    )


async def search_attack_techniques(
    params: TechniqueSearchInput, db: AsyncDatabase
) -> dict[str, Any]:
    matches = get_catalog().search(params.keyword, limit=SEARCH_LIMIT)
    return {"attack_catalog": [t.model_dump() for t in matches], "total": len(matches)}


class TechniqueLookupInput(ToolInput):
    technique_id: Annotated[str, StringConstraints(max_length=12)] = Field(
        description="ATT&CK technique ID, e.g. T1059.001."
    )


async def lookup_attack_technique(
    params: TechniqueLookupInput, db: AsyncDatabase
) -> dict[str, Any]:
    technique = get_catalog().get_technique(params.technique_id)
    if technique is None:
        raise ToolError(f"{params.technique_id} is not a technique in ATT&CK v20")
    result: dict[str, Any] = {"attack_catalog": technique.model_dump()}
    if technique.revoked or technique.deprecated:
        status = "revoked" if technique.revoked else "deprecated"
        result["note"] = f"{technique.id} is {status}; search for its current replacement"
    return result
