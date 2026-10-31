"""CLI companion for Phase 4.

The Flask UI uses the same phase4_remediation functions, so CLI and web
behaviour share the same approval/verification safeguards.
"""

from __future__ import annotations

import argparse
import json
import sys

import phase4_remediation as p4


def print_json(value):
    print(json.dumps(value, indent=2, ensure_ascii=False))


def print_tasks(state):
    rows = p4.task_rows(state)
    if not rows:
        print("No Phase 4 tasks found.")
        return

    headers = ["Task", "Finding", "Status", "Risk", "Action", "Approval", "Target"]
    data = [
        [
            str(row["task_id"]),
            str(row["finding_id"]),
            str(row["status"]),
            str(row["risk"]),
            str(row["action"]),
            str(row["approval"]),
            str(row["target"] or ""),
        ]
        for row in rows
    ]
    widths = [max(len(headers[i]), *(len(row[i]) for row in data)) for i in range(len(headers))]

    def line(values):
        return " | ".join(str(value).ljust(widths[i]) for i, value in enumerate(values))

    print(line(headers))
    print("-+-".join("-" * width for width in widths))
    for row in data:
        print(line(row))


def main():
    parser = argparse.ArgumentParser(description="Phase 4 — user-authorised remediation and action tracking")
    sub = parser.add_subparsers(dest="command", required=True)

    init_parser = sub.add_parser("init", help="Create/refresh Phase 4 from current Phase 3 output")
    init_parser.add_argument("--force", action="store_true")

    sub.add_parser("list", help="List Phase 4 remediation tasks")

    show = sub.add_parser("show", help="Show one Phase 4 task")
    show.add_argument("task_id")

    approve = sub.add_parser("approve", help="Explicitly approve an execution-changing action")
    approve.add_argument("task_id")

    reject = sub.add_parser("reject", help="Reject/skip a proposed action")
    reject.add_argument("task_id")

    for command, status, help_text in [
        ("start", "in_progress", "Mark an approved/manual task in progress"),
        ("submitted", "submitted", "Mark an external request as submitted"),
        ("pending", "pending_external_confirmation", "Mark an action pending provider confirmation"),
        ("complete", "completed", "Mark a manual/review action completed"),
        ("fail", "failed", "Mark an action failed"),
        ("skip", "skipped", "Skip a task"),
    ]:
        cmd = sub.add_parser(command, help=help_text)
        cmd.add_argument("task_id")
        cmd.set_defaults(target_status=status)

    preview = sub.add_parser("preview-local", help="Preview selected tracker-cookie metadata only")
    preview.add_argument("task_id")
    preview.add_argument("--domain", action="append", default=[])

    execute = sub.add_parser("execute-local", help="Execute approved selected tracker-cookie cleanup")
    execute.add_argument("task_id")
    execute.add_argument("--domain", action="append", required=True)
    execute.add_argument("--confirm", action="store_true")

    verify = sub.add_parser("verify-local", help="Re-audit a completed local tracker cleanup")
    verify.add_argument("task_id")

    args = parser.parse_args()

    if args.command == "init":
        state = p4.initialize_state(force=args.force)
        print("Phase 4 state created/refreshed.")
        print_json(state.get("summary", {}))
        return

    state = p4.load_or_initialize_state()

    if args.command == "list":
        print_tasks(state)
        return
    if args.command == "show":
        print_json(p4.get_task(state, args.task_id))
        return
    if args.command == "approve":
        task = p4.approve_task(state, args.task_id)
        print(f"{task['task_id']} approved. Status: {task['status']}")
        return
    if args.command == "reject":
        task = p4.reject_task(state, args.task_id)
        print(f"{task['task_id']} skipped by user.")
        return
    if args.command in {"start", "submitted", "pending", "complete", "fail", "skip"}:
        task = p4.transition_task(state, args.task_id, args.target_status)
        print(f"{task['task_id']} -> {task['status']}")
        return
    if args.command == "preview-local":
        result = p4.preview_local_tracker_cleanup(
            state,
            args.task_id,
            domain_groups=args.domain or None,
        )
        print_json(result)
        print("Preview only: cookie values were not read and nothing was deleted.")
        return
    if args.command == "execute-local":
        if not args.confirm:
            raise PermissionError(
                "Execution blocked. Review preview-local, close the browser, then add --confirm."
            )
        print_json(
            p4.execute_local_tracker_cleanup(
                state,
                args.task_id,
                domain_groups=args.domain,
                confirmed=True,
            )
        )
        return
    if args.command == "verify-local":
        print_json(p4.verify_local_tracker_cleanup(state, args.task_id))
        return


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Phase 4 error: {exc}", file=sys.stderr)
        raise SystemExit(1)
