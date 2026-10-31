"""Rebuild ONLY the association panel from saved decisions. No network/API calls.

Default is preview. --apply backs up and updates latest_phase3_analysis.json.
This does not change ownership answers, risk scores, Phase 4 tasks or approvals.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from phase3_associations import build_public_associations


def rebuild(project_dir: Path, *, apply: bool = False) -> dict:
    aggregate_path = project_dir / 'reports/aggregate/latest_aggregate_internal.json'
    analysis_path = project_dir / 'reports/phase3/latest_phase3_analysis.json'
    for path in (aggregate_path, analysis_path):
        if not path.is_file():
            raise FileNotFoundError(f'Missing required report: {path}')
    aggregate_bytes = aggregate_path.read_bytes()
    analysis_bytes = analysis_path.read_bytes()
    report = json.loads(aggregate_bytes.decode('utf-8-sig'))
    saved = json.loads(analysis_bytes.decode('utf-8-sig'))
    if report.get('artifact_type') != 'aggregated_footprint_report':
        raise ValueError('The Phase 2 file is not an aggregate report.')
    if saved.get('artifact_type') != 'phase3_ai_analysis':
        raise ValueError('The Phase 3 file is not an analysis report.')
    if not report.get('run_id') or report.get('run_id') != saved.get('source_run_id'):
        raise ValueError('Phase 2 and Phase 3 belong to different runs. No file was changed. Restart Phase 3 on the intended Phase 2 scan.')
    associations = build_public_associations(report, saved.get('analyses', []))
    if any(r['reason'] in {'excluded_source_changed_restart_phase3', 'excluded_duplicate_finding_id'}
           for r in associations.get('source_audit', [])):
        raise ValueError('Evidence/ID bindings changed or duplicate IDs exist. Refusing to reuse these decisions. Restart Phase 3.')
    result = {'source_run_id': report['run_id'], 'source_counts': associations['source_counts'],
              'organizations': associations['organizations'], 'roles': associations['roles'],
              'association_rows': associations.get('association_rows', []),
              'source_audit': associations['source_audit'], 'warnings': associations['warnings'],
              'applied': False}
    if apply:
        saved['public_associations'] = associations
        saved['association_rebuild_at'] = datetime.now(timezone.utc).isoformat()
        # Detect another scan/write before overwriting the saved JSON.
        if aggregate_path.read_bytes() != aggregate_bytes or analysis_path.read_bytes() != analysis_bytes:
            raise RuntimeError('Reports changed during rebuild. Stop the scan and retry.')
        stamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')
        backup = analysis_path.with_name(f'phase3_before_association_fix_{stamp}.json')
        backup.write_bytes(analysis_bytes)
        fd, temp_name = tempfile.mkstemp(dir=analysis_path.parent, prefix='.association_rebuild_', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(saved, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_name, analysis_path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
        result.update(applied=True, backup=str(backup))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='Back up and replace only the saved association panel.')
    parser.add_argument('--project-dir', type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    try:
        result = rebuild(args.project_dir.resolve(), apply=args.apply)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f'Association rebuild stopped: {exc}', file=sys.stderr)
        return 1
    print('Run:', result['source_run_id'])
    print('Counts:', json.dumps(result['source_counts']))
    print('Organization-role rows (max 3):')
    if result.get('association_rows'):
        for row in result['association_rows'][:3]:
            print('  - {} | {} | support={} | {}'.format(
                row.get('organization'), row.get('role'), row.get('support_count', 1), row.get('pairing_basis')))
    else:
        print('  Not reliably established')
    print('\nSaved identity decisions and association extraction (different stages):')
    print('accepted=True means the finding is still accepted, even when association_evidence=False.')
    for row in result['source_audit']:
        print('{finding_id} | decision={user_decision} | accepted={accepted} | '
              'association_evidence={contributed} | {reason} | {title}'.format(**row))
        fields = row.get('decision_fields', {})
        if row['user_decision'] in {'rejected', 'unsure'} or row.get('decision_conflict'):
            print('    saved user_verification={} | saved verification_audit.response={}{}'.format(
                fields.get('user_verification', 'missing'),
                fields.get('verification_audit_response', 'missing'),
                ' | CONFLICT: review saved answers' if row.get('decision_conflict') else ''))
    for warning in result['warnings']:
        print('\nWARNING:', warning)
    print('\nUpdated association panel; other Phase 3/4 state unchanged.' if result['applied']
          else '\nPreview only: no files changed. Run again with --apply to save.')
    if result.get('backup'):
        print('Backup:', result['backup'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
