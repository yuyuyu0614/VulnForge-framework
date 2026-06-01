"""Multi-agent collaboration test — Architect + Auditor pipeline on vuln_demo."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from db import get_db
from agents.scheduler import CollaborationScheduler, get_total_token_count, get_budget_percentage

DEMO_DIR = Path(__file__).resolve().parent / "fixtures" / "vuln_demo"


def test_two_agent_collaboration():
    db = get_db()
    db.init_schema()

    hook_count_before = db.get_hook_count()
    finding_count_before = db.get_finding_count()

    print(f"Hooks before:    {hook_count_before}")
    print(f"Findings before: {finding_count_before}")
    print()

    scheduler = CollaborationScheduler(db=db)
    findings = scheduler.run_collaborative_audit(str(DEMO_DIR))

    # Verify DB state — hooks and findings must exist
    assert db.get_hook_count() > 0, "No hooks in database"
    assert db.get_finding_count() > 0, "No findings in database"
    # Assertions against THIS run's results
    assert len(findings) >= 1, (
        f"Auditor did not find any vulnerabilities (got {len(findings)})"
    )

    # Token budget check
    total_tokens = get_total_token_count(db)
    budget_pct = get_budget_percentage(db)
    print(f"  Total tokens: {total_tokens:,}")
    print(f"  Budget used:  {budget_pct:.1f}%")
    assert total_tokens > 0, "No token usage recorded"

    print(f"\n  [PASS] Multi-agent collaboration test passed")
    return True


if __name__ == "__main__":
    success = test_two_agent_collaboration()
    sys.exit(0 if success else 1)
