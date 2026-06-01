# Changelog

## v1.3.1 — Butian Compliance Update (2026-06-01)

### Field Experience
- Pure info-leak vulnerabilities rejected by SRC platforms without proven exploit chain
- Frontend source leaks, log leaks, error message leaks need demonstrated impact
- Auto-scan false positives extremely high; manual verification required before submission

### Changes
- `apply_butian_compliance()`: Auto-downgrade info-leak findings (CWE-200/532/209/798/204/548/693)
- `filter_butian_submittable()`: Split findings into submittable vs needs-evidence
- `BUTIAN_LOW_IMPACT_CWE` dict drives severity downgrade logic

### Priority Adjustment
Info leak weight reduced by one tier (high->medium, medium->low, low->info)

---

## v1.3.0 — Multi-Platform SRC Readiness

### New Modules
- `false_positive_filter.py`: Data-flow reachability analysis, 93% FP reduction
- `cwe_classifier.py`: CWE classification (10 categories)
- `report_generator.py`: Multi-format report export with PoC generation

---

## v1.2.0 — Collaboration & Scheduling

- Multi-agent collaboration scheduler with retry and auto-growth
- VulTrial 4-role adversarial verification
- DispatchCenter unified control panel
- Event-driven UI refresh
