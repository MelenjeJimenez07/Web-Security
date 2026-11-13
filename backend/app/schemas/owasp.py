"""Pydantic schemas for the OWASP Top 10:2025 catalog."""

from pydantic import BaseModel, ConfigDict


class OwaspCategoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    code: str
    rank: int
    name: str
    name_es: str
    short_summary: str
    description: str
    remediation_guidance: str
    cwe_examples: list[str]
    is_new_in_2025: bool
    reference_url: str
