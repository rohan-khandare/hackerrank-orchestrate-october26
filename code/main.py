
import csv
import json
import re
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
EVIDENCE_ROOT = DATASET / "evidence"
OUTPUT = ROOT / "output.csv"

OUTPUT_FIELDS = ["case_id", "deletion_status", "steps_json"]

NON_DELETE = [
    "marketing opt-out", "marketing opt out", "stop marketing",
    "correct my data", "correct my personal data", "rectify my",
    "access my data", "export my data", "download my data",
    "show me my data", "port my data", "unsubscribe",
]

DELETE_TERMS = [
    "delete", "deletion", "deleted", "deleting", "erase", "erasure",
    "erased", "remove", "removal", "purge", "wipe", "account closure",
    "close my account", "close this account", "close the account",
    "eliminar", "eliminación", "borrar mi cuenta",
    "supprimer mon compte", "suppression du compte",
    "effacer mes données", "削除",
]


def read_csv(name):
    path = DATASET / name
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def parse_time(value):
    if not value:
        return None
    try:
        value = value.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def before_cutoff(timestamp, cutoff):
    """Unknown timestamps are not accepted as proof of a past state."""
    observed = parse_time(timestamp)
    return observed is not None and cutoff is not None and observed <= cutoff


def norm(value):
    return str(value or "").strip().casefold()


def classify_request(request):
    text = norm(request.get("request_text"))

    if any(term in text for term in NON_DELETE):
        return "NOT_APPLICABLE"

    if any(term in text for term in DELETE_TERMS):
        return "DELETE"

    return "REVIEW"


def resolve_identity(request, identities, audit):
    email = norm(request.get("email"))
    cutoff = parse_time(request.get("audit_at"))
    matches = set()

    for row in identities:
        if norm(row.get("email")) == email:
            matches.add(row["user_id"])

    for event in audit:
        if norm(event.get("field_name")) != "email":
            continue

        event_time = parse_time(event.get("event_time"))
        if cutoff and event_time and event_time > cutoff:
            continue

        if email in (norm(event.get("old_value")), norm(event.get("new_value"))):
            matches.add(event["user_id"])

    if len(matches) == 1:
        return next(iter(matches))

    return None


def get_aliases(request, user_id, audit):
    aliases = {norm(request.get("email"))}
    cutoff = parse_time(request.get("audit_at"))

    if not user_id:
        return {a for a in aliases if a}

    for event in audit:
        if event.get("user_id") != user_id:
            continue
        if norm(event.get("field_name")) != "email":
            continue

        event_time = parse_time(event.get("event_time"))
        if cutoff and event_time and event_time > cutoff:
            continue

        for value in (event.get("old_value"), event.get("new_value")):
            if norm(value):
                aliases.add(norm(value))

    return {a for a in aliases if a}


def evidence_path(item):
    relative = Path(item["file_path"])

    if relative.parts and relative.parts[0].casefold() == "evidence":
        relative = Path(*relative.parts[1:])

    return EVIDENCE_ROOT / relative


def system_from_path(path):
    name = str(path).casefold()

    mappings = [
        ("account", "account_service"),
        ("search", "search_service"),
        ("analytics", "analytics_platform"),
        ("support", "support_platform"),
        ("integration", "integration_service"),
        ("backup", "backup_service"),
        ("export", "export_service"),
        ("security", "security_service"),
        ("marketing", "marketing_service"),
        ("email", "email_service"),
        ("cache", "cache_service"),
    ]

    for token, system in mappings:
        if token in name:
            return system

    return "unknown_system"


def discover_json(node, path_parts, file_id, aliases, cutoff, results):
    if isinstance(node, dict):
        scalar_values = [
            norm(v) for v in node.values()
            if isinstance(v, (str, int, float, bool))
        ]

        matches = [
            alias for alias in aliases
            if any(alias in value for value in scalar_values)
        ]

        resource_id = node.get("resource_id")
        observed = node.get("observed_at") or node.get("event_time")

        if resource_id and matches and before_cutoff(observed, cutoff):
            system = next(
                (
                    part for part in path_parts
                    if part.endswith("_service") or part.endswith("_platform")
                ),
                "unknown_system",
            )

            key = (system, str(resource_id))
            results[key] = {
                "file_id": file_id,
                "system_id": system,
                "resource_id": str(resource_id),
                "fields": node,
            }

        for key, value in node.items():
            discover_json(
                value, path_parts + [key], file_id,
                aliases, cutoff, results,
            )

    elif isinstance(node, list):
        for item in node:
            discover_json(
                item, path_parts, file_id, aliases, cutoff, results
            )


def find_evidence(request, user_id, data):
    cutoff = parse_time(request.get("audit_at"))
    aliases = get_aliases(request, user_id, data["audit"])
    found = {}

    for item in data["manifest"]:
        if not before_cutoff(item.get("captured_at"), cutoff):
            continue

        path = evidence_path(item)
        if not path.is_file():
            continue

        suffix = path.suffix.casefold()
        file_id = item.get("file_id", "")

        if suffix == ".json":
            try:
                with path.open("r", encoding="utf-8-sig") as f:
                    payload = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue

            discover_json(
                payload, [], file_id, aliases, cutoff, found
            )

        elif suffix in {".log", ".txt", ".sql"}:
            try:
                lines = path.read_text(
                    encoding="utf-8-sig", errors="replace"
                ).splitlines()
            except OSError:
                continue

            for line in lines:
                lowered = norm(line)
                if not any(alias in lowered for alias in aliases):
                    continue

                # Only identify resource IDs when they appear on a matching
                # line. The actual record meaning still needs review.
                ids = re.findall(
                    r"\b(?:account|search|analytics|support|"
                    r"audit_record|data_flow|backup|export)_\d+\b",
                    line,
                    flags=re.IGNORECASE,
                )

                for resource_id in ids:
                    system = system_from_path(path)
                    key = (system, resource_id)
                    found[key] = {
                        "file_id": file_id,
                        "system_id": system,
                        "resource_id": resource_id,
                        "fields": {"evidence_line": line.strip()},
                    }

    return list(found.values())


def action_for(record):
    system = record["system_id"]
    fields = record["fields"]
    resource = record["resource_id"]

    if system == "integration_service":
        enabled = fields.get("enabled")
        if enabled is True:
            return ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE",
                    "DISABLE_DATA_FLOW", "DISABLED",
                    "VERIFY_DATA_FLOW_DISABLED")
        return None

    if system == "backup_service":
        if fields.get("restore_allowed") is True:
            return ("REPORT_RESTORE_RISK", "ACTIVE",
                    "BLOCK_RESTORE", "BLOCKED",
                    "VERIFY_RESTORE_BLOCKED")
        return None

    if system == "analytics_platform":
        return ("REPORT_EXPOSED_PII", "PRESENT",
                "ANONYMIZE_RECORD", "ANONYMIZED",
                "VERIFY_RECORD_ANONYMIZED")

    if system == "support_platform":
        return ("REPORT_EXPOSED_PII", "PRESENT",
                "REDACT_RECORD", "REDACTED",
                "VERIFY_RECORD_REDACTED")

    if system in ("search_service", "account_service",
                  "export_service", "marketing_service",
                  "cache_service"):
        return ("REPORT_REMAINING_RECORD", "PRESENT",
                "DELETE_RECORD", "ABSENT",
                "VERIFY_RECORD_ABSENT")

    if system == "security_service":
        return None

    return None


def make_step(number, phase, system, resource, operation, state, evidence=""):
    return {
        "step_no": number,
        "phase": phase,
        "system_id": system,
        "resource_id": resource,
        "operation": operation,
        "state": state,
        "evidence_id": evidence,
    }


def analyze_request(request, data):
    intent = classify_request(request)

    if intent == "NOT_APPLICABLE":
        return "NOT_APPLICABLE", []

    user_id = resolve_identity(
        request, data["identities"], data["audit"]
    )

    records = find_evidence(request, user_id, data)

    findings = []
    remediations = []
    verifications = []
    seen = set()

    # Turn matching evidence into candidate findings and proposed actions.
    # Findings cite observed evidence; proposed actions are not represented
    # as completed work.
    for record in records:
        action = action_for(record)
        if not action:
            continue

        finding_op, finding_state, fix_op, fix_state, verify_op = action
        key = (record["system_id"], record["resource_id"], fix_op)

        if key in seen:
            continue
        seen.add(key)

        findings.append(make_step(
            0, "FINDING", record["system_id"], record["resource_id"],
            finding_op, finding_state, record["file_id"],
        ))

        remediations.append(make_step(
            0, "REMEDIATION", record["system_id"], record["resource_id"],
            fix_op, fix_state, "",
        ))

        verifications.append(make_step(
            0, "VERIFICATION", record["system_id"], record["resource_id"],
            verify_op, fix_state, "",
        ))

    # Disable active flows and block restores before downstream cleanup.
    remediations.sort(key=lambda s: (
        0 if s["operation"] in ("DISABLE_DATA_FLOW", "BLOCK_RESTORE") else 1
    ))

    steps = findings + remediations + verifications

    for number, step in enumerate(steps, start=1):
        step["step_no"] = number

    if intent == "REVIEW":
        return "INCOMPLETE", steps

    if findings:
        return "INCOMPLETE", steps

    # No matching evidence is not proof that all data was deleted.
    # Treat it as unresolved rather than claiming COMPLETE.
    return "INCOMPLETE", steps


def main():
    data = {
        "requests": read_csv("deletion_requests.csv"),
        "identities": read_csv("user_identities.csv"),
        "audit": read_csv("user_audit_log.csv"),
        "activities": read_csv("system_activity.csv"),
        "rules": read_csv("deletion_rules.csv"),
        "manifest": read_csv("evidence_files.csv"),
    }

    rows = []

    for request in data["requests"]:
        status, steps = analyze_request(request, data)
        rows.append({
            "case_id": request["case_id"],
            "deletion_status": status,
            "steps_json": json.dumps(
                steps, ensure_ascii=False, separators=(",", ":"),
                sort_keys=True,
            ),
        })

    rows.sort(key=lambda row: row["case_id"])

    with OUTPUT.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generated {OUTPUT}")
    print(f"Requests processed: {len(rows)}")
    print("Status counts:")

    for status in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
        print(
            f"  {status}: "
            f"{sum(row['deletion_status'] == status for row in rows)}"
        )


if __name__ == "__main__":
    main()
