"""Idempotent database seeding for the OWASP Top 10:2025 catalog."""

import logging

from sqlalchemy.orm import Session

from app.db.owasp_catalog import OWASP_TOP_10_2025_CATALOG
from app.db.session import SyncSessionLocal
from app.models.owasp import OwaspCategory

logger = logging.getLogger(__name__)


def seed_owasp_categories(session: Session) -> int:
    """Upsert all 10 OWASP Top 10:2025 categories idempotently.

    Returns the number of newly inserted records.
    """
    inserted = 0
    for item in OWASP_TOP_10_2025_CATALOG:
        existing = session.get(OwaspCategory, item["code"])
        if existing is None:
            session.add(OwaspCategory(**item))
            inserted += 1
        else:
            existing.rank = item["rank"]
            existing.name = item["name"]
            existing.name_es = item["name_es"]
            existing.short_summary = item["short_summary"]
            existing.description = item["description"]
            existing.remediation_guidance = item["remediation_guidance"]
            existing.cwe_examples = item["cwe_examples"]
            existing.is_new_in_2025 = item["is_new_in_2025"]
            existing.reference_url = item["reference_url"]
    session.commit()
    return inserted


def main() -> None:
    """CLI entrypoint for seeding initial reference tables."""
    logging.basicConfig(level=logging.INFO)
    with SyncSessionLocal() as session:
        inserted = seed_owasp_categories(session)
        logger.info("OWASP Top 10:2025 catalog synchronized (%s inserted).", inserted)


if __name__ == "__main__":
    main()
