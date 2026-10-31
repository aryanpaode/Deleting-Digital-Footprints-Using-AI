"""Offline regression tests. All decisions and identities below are test fixtures.
No Gmail, search, OpenAI API, browser database or real user's reports are touched.
"""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import phase3_associations as pa
import run_phase3 as p3
from repair_phase3_associations import rebuild

NAME = 'Karan Mehra'


def make_row(title=None, snippet='', url='https://example.org/doctor/one', **kwargs):
    row = {'title': title or 'Dr. Karan Mehra | Orthopaedic Surgeon', 'snippet': snippet,
           'url': url, 'source_category': 'Professional profile', 'identity_status': 'Possible',
           'entities': {'organizations': [], 'job_titles': []}}
    row.update(kwargs)
    return row


def report(rows, name=NAME):
    return {'artifact_type': 'aggregated_footprint_report', 'run_id': 'TEST-RUN',
            'input_profile': {'full_name': name},
            'layers': {'phase_2A_public': {'results': rows}}}


def answers(values):
    return [{'finding_id': 'P2A-%03d' % i, 'user_verification': v,
             'verification_audit': {'response': v}, 'needs_user_verification': False}
            for i, v in enumerate(values, 1)]


class AssociationGuardTests(unittest.TestCase):
    def test_no_overrides_manual_visual_confirmation(self):
        row = make_row(snippet='Karan Mehra is a student at Oxford University.',
                       visual_identity={'manual_verification_status': 'confirmed'})
        r = pa.build_public_associations(report([row]), answers(['rejected']))
        self.assertEqual(r['organizations'], [])
        self.assertEqual(r['roles'], [])
        self.assertEqual(r['source_audit'][0]['reason'], 'excluded_user_no')

    def test_saved_no_overrides_later_ai_confirmation(self):
        a = answers(['confirmed'])
        a[0]['verification_audit']['response'] = 'No'
        r = pa.build_public_associations(report([make_row()]), a)
        self.assertEqual(r['evidence'], [])

    def test_decision_variants_fail_closed(self):
        for value in ('No', 'NO', 'n', False, {'response': 'No'}, 'rejected'):
            with self.subTest(value=value):
                r = pa.build_public_associations(report([make_row()]), answers([value]))
                self.assertEqual(r['source_counts']['user_no'], 1)
                self.assertEqual(r['roles'], [])

    def test_unsure_not_profile_evidence_even_when_visual_yes(self):
        row = make_row(visual_identity={'manual_verification_status': 'confirmed'})
        self.assertEqual(pa.build_public_associations(report([row]), answers(['unsure']))['roles'], [])

    def test_missing_analysis_never_accepted(self):
        self.assertEqual(pa.build_public_associations(report([make_row(identity_status='Confirmed')]), [])['roles'], [])

    def test_deterministic_confirmed_accepted_without_repeat_question(self):
        r = pa.build_public_associations(report([make_row(identity_status='Confirmed')]), answers(['not_required']))
        self.assertIn('Orthopaedic Surgeon', r['roles'])

    def test_strong_without_yes_is_excluded(self):
        r = pa.build_public_associations(report([make_row(identity_status='Strong')]), answers(['not_required']))
        self.assertEqual(r['roles'], [])

    def test_duplicate_url_no_veto(self):
        rows = [make_row(), make_row(url='https://www.example.org/doctor/one?utm_source=test')]
        r = pa.build_public_associations(report(rows), answers(['confirmed', 'rejected']))
        self.assertEqual(r['roles'], [])
        self.assertEqual(r['source_audit'][0]['reason'], 'excluded_duplicate_source_has_no_or_unsure')

    def test_same_domain_distinct_records_not_merged(self):
        rows = [make_row(), make_row('Karan Mehra | Student | Oxford University', url='https://example.org/doctor/two')]
        r = pa.build_public_associations(report(rows), answers(['confirmed', 'rejected']))
        self.assertIn('Orthopaedic Surgeon', r['roles'])
        self.assertNotIn('Student', r['roles'])

    def test_duplicate_rows_do_not_double_vote(self):
        rows = [make_row(), make_row()]
        r = pa.build_public_associations(report(rows), answers(['confirmed', 'confirmed']))
        self.assertEqual(r['verified_evidence_count'], 1)
        self.assertEqual(r['confidence'], 'Low')

    def test_same_run_reordered_source_cannot_inherit_yes(self):
        rows = [make_row(), make_row('Karan Mehra | Student | Oxford University', url='https://example.org/two')]
        source = report(rows)
        a = answers(['confirmed', 'rejected'])
        for i, row in enumerate(rows):
            a[i]['source_binding'] = pa.source_binding(source, row)
        source['layers']['phase_2A_public']['results'].reverse()
        r = pa.build_public_associations(source, a)
        self.assertEqual(r['roles'], [])
        self.assertTrue(all(x['reason'] == 'excluded_source_changed_restart_phase3' for x in r['source_audit']))

    def test_duplicate_ids_excluded(self):
        a = answers(['confirmed'])
        r = pa.build_public_associations(report([make_row()]), a + a)
        self.assertEqual(r['roles'], [])

    def test_31_accepted_medical_sources_and_four_rejected_distractors(self):
        # Deliberately simulated 31/4 split; not the user's actual saved answers.
        rows = [make_row('Dr. Karan Mehra | Senior Consultant , Orthopaedics',
                         'Karan Mehra is an Orthopaedic Surgeon at Apollo Hospitals.',
                         url='https://example.org/doctor/%d' % i) for i in range(31)]
        rows += [make_row('Karan Mehra | Student | Oxford University',
                          'Karan Mehra is Vice President at HEALKARE PRIVATE LIMITED.',
                          url='https://other.example.org/%d' % i) for i in range(4)]
        r = pa.build_public_associations(report(rows), answers(['confirmed'] * 31 + ['rejected'] * 4))
        self.assertEqual(r['source_counts']['accepted_sources'], 31)
        self.assertEqual(r['source_counts']['user_no'], 4)
        self.assertEqual(r['organizations'], ['Apollo Hospitals'])
        self.assertEqual(set(r['roles']), {'Senior Consultant — Orthopaedics', 'Orthopaedic Surgeon'})
        self.assertEqual(len(r['evidence']), 31)  # Not a first-12-source preview.
        self.assertFalse(any(e['contributed'] for e in r['source_audit'][31:]))

    def test_healthcare_menu_and_entities_are_not_profile_claims(self):
        row = make_row(snippet='General Physician ENT Ob-Gynae Paediatrics Neurology Lab Tests Find a',
                       entities={'organizations': ['General Physician ENT Ob-Gynae Paediatrics Neurology Lab',
                                                   'HEALKARE PRIVATE LIMITED', 'Oxford University'],
                                 'job_titles': ['student', 'vice president']})
        r = pa.build_public_associations(report([row]), answers(['confirmed']))
        self.assertEqual(r['organizations'], [])
        self.assertEqual(r['roles'], ['Orthopaedic Surgeon'])

    def test_legal_footer_and_other_person_do_not_contribute(self):
        row = make_row(extracted_content=(
            'Dr. Karan Mehra is an Orthopaedic Surgeon at Apollo Hospitals.\n'
            'Student Ravi Sharma at Oxford University.\n'
            'Copyright HEALKARE PRIVATE LIMITED. All rights reserved.'))
        r = pa.build_public_associations(report([row]), answers(['confirmed']))
        self.assertEqual(r['organizations'], ['Apollo Hospitals'])
        self.assertNotIn('Student', r['roles'])

    def test_colleague_role_not_assigned_to_subject(self):
        row = make_row(snippet='Karan Mehra welcomed student Ravi Sharma from Oxford University.',
                       extracted_content='Vice President Ravi Sharma introduces Dr. Karan Mehra.')
        r = pa.build_public_associations(report([row]), answers(['confirmed']))
        self.assertEqual(r['organizations'], [])
        self.assertEqual(r['roles'], ['Orthopaedic Surgeon'])

    def test_profile_affiliation_in_title_is_usable(self):
        row = make_row('Karan MEHRA | Apollo Hospitals, Chennai')
        r = pa.build_public_associations(report([row]), answers(['confirmed']))
        self.assertEqual(r['organizations'], ['Apollo Hospitals'])

    def test_student_degree_and_entities_are_distinct(self):
        row = make_row('Arjun MEHRA | Student | Bachelor of Technology | NMIMS', 'Student at MPSTME.')
        r = pa.build_public_associations(report([row], 'Arjun Mehra'), answers(['confirmed']))
        self.assertEqual(set(r['organizations']), {'NMIMS', 'MPSTME'})
        self.assertEqual(r['roles'], ['Student'])

    def test_faculty_roles_specific_not_stray_student(self):
        row = make_row('Faculty Example | Assistant Professor | NMIMS',
                       'Faculty Example is an Assistant Professor at MPSTME.',
                       entities={'organizations': ['college', 'a top engineering college in Mumbai was'],
                                 'job_titles': ['Student', 'Director']})
        r = pa.build_public_associations(report([row], 'Faculty Example'), answers(['confirmed']))
        self.assertEqual(set(r['organizations']), {'NMIMS', 'MPSTME'})
        self.assertEqual(r['roles'], ['Assistant Professor'])

    def test_organization_variants_deduplicated_and_capped_at_four(self):
        names = ['Example Company', 'Example Company Limited', 'Second Company Limited',
                 'Third University', 'Fourth Hospitals', 'Fifth Bank']
        rows = [make_row('Rohan Malhotra - ' + n, url='https://example.org/%d' % i) for i, n in enumerate(names)]
        r = pa.build_public_associations(report(rows, 'Rohan Malhotra'), answers(['confirmed'] * len(rows)))
        self.assertEqual(len(r['organizations']), 4)
        self.assertIn('Example Company Limited', r['organizations'])
        self.assertNotIn('Example Company', r['organizations'])

    def test_no_current_status_inference_and_no_claims_from_retrieval_date(self):
        row = make_row(discovered_at='2026-01-01T00:00:00+00:00')
        r = pa.build_public_associations(report([row]), answers(['confirmed']))
        self.assertEqual(r['evidence_recency'], 'Mostly undated')
        self.assertNotIn('current_organization', r)
        self.assertNotIn('status', r)

    def test_every_displayed_value_has_accepted_source_quote(self):
        row = make_row(snippet='Karan Mehra is an Orthopaedic Surgeon at Apollo Hospitals.')
        r = pa.build_public_associations(report([row]), answers(['confirmed']))
        vals = set(r['organizations'] + r['roles'])
        self.assertEqual(vals, {c['value'] for c in r['claims']})
        self.assertTrue(all(c['finding_id'] == 'P2A-001' for c in r['claims']))
        self.assertTrue(all(c['evidence_excerpt'] for c in r['claims']))

    def test_blank_name_does_not_guess_from_entity_list(self):
        r = pa.build_public_associations(report([make_row()], ''), answers(['confirmed']))
        self.assertEqual(r['roles'], [])


class IntegrationTests(unittest.TestCase):
    def test_source_binding_attached_before_analysis(self):
        r = report([make_row()])
        compact = p3.build_compact_ai_input(r)
        safe = p3.sanitized_findings(r, compact)
        self.assertEqual(safe[0]['_local_source_binding'], pa.source_binding(r, r['layers']['phase_2A_public']['results'][0]))
        self.assertNotIn(NAME, json.dumps(safe))

    def test_short_identifier_does_not_corrupt_system_id_or_binding(self):
        r = report([make_row()])
        r['input_profile']['username'] = 'a'
        compact = p3.build_compact_ai_input(r)
        safe = p3.sanitized_findings(r, compact)
        self.assertEqual(safe[0]['finding_id'], 'P2A-001')
        self.assertEqual(safe[0]['_local_source_binding'], pa.source_binding(r, r['layers']['phase_2A_public']['results'][0]))

    def test_model_output_reordered_binds_by_id_and_local_hash_not_sent(self):
        rows = [make_row(), make_row(url='https://example.org/2')]
        r = report(rows)
        compact = p3.build_compact_ai_input(r)
        safe = p3.sanitized_findings(r, compact)
        parsed = {'analyses': [{'finding_id': 'P2A-002'}, {'finding_id': 'P2A-001'}]}
        create_calls = []
        def create(**kwargs):
            create_calls.append(kwargs)
            return SimpleNamespace(output_text=json.dumps(parsed))
        client = SimpleNamespace(responses=SimpleNamespace(create=create))
        with patch.object(p3, 'validate_ai_analysis', side_effect=lambda x: x):
            out = p3.request_analysis(client, safe, 'test', 'test')
        self.assertNotIn('_local_source_binding', create_calls[0]['input'])
        self.assertEqual(out[0]['source_binding'], pa.source_binding(r, rows[1]))

    def test_rejected_and_unsure_content_not_sent_to_cross_layer(self):
        a = answers(['confirmed', 'rejected', 'unsure'])
        a[1]['risk_explanation'] = 'POISON REJECTED UNIVERSITY'
        a[2]['risk_explanation'] = 'POISON UNKNOWN ROLE'
        payload = p3.build_cross_layer_input({}, a)
        self.assertEqual(len(payload['analyses']), 1)
        self.assertNotIn('POISON', json.dumps(payload))
        self.assertEqual(payload['excluded_identity_decision_counts'], {'rejected': 1, 'unsure': 1})

    def test_reassessment_cannot_be_requested_for_rejected_id(self):
        a = answers(['rejected'])
        with patch.object(p3, 'request_analysis') as request:
            self.assertEqual(p3.reassess_confirmed_findings(None, a, ['P2A-001'], [{'finding_id': 'P2A-001'}]), 0)
            request.assert_not_called()
        self.assertEqual(a[0]['user_verification'], 'rejected')

    def test_save_refuses_changed_source(self):
        r = report([make_row()])
        a = answers(['confirmed'])
        a[0]['source_binding'] = pa.source_binding(r, r['layers']['phase_2A_public']['results'][0])
        r['layers']['phase_2A_public']['results'][0]['title'] = 'Different Person'
        with self.assertRaisesRegex(RuntimeError, 'Phase 2 evidence changed'):
            p3.save_phase3_outputs(r, a, {}, 0, {})

    def test_automatic_confirmation_has_not_required_outcome(self):
        a = [{'finding_id': 'P2A-001', 'needs_user_verification': True, 'recommended_action': 'verify_identity'}]
        p3.apply_deterministic_verification_policy([{'finding_id': 'P2A-001', 'identity_status': 'Confirmed'}], a)
        self.assertFalse(a[0]['needs_user_verification'])
        self.assertEqual(a[0]['user_verification'], 'not_required')

    def files(self, root):
        r = report([make_row(snippet='Karan Mehra is a senior consultant at Apollo Hospitals.')])
        saved = {'artifact_type': 'phase3_ai_analysis', 'source_run_id': r['run_id'],
                 'run_time': 'OLD-TIME', 'analyses': answers(['confirmed']),
                 'cross_layer_assessment': {'overall_risk_score': 20},
                 'public_associations': {'organizations': ['OLD-WRONG-VALUE']}}
        paths = [root/'reports/aggregate/latest_aggregate_internal.json',
                 root/'reports/phase3/latest_phase3_analysis.json']
        for path, value in zip(paths, [r, saved]):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value), encoding='utf-8')
        return paths, saved

    def test_rebuild_preview_does_not_write(self):
        with tempfile.TemporaryDirectory() as temp:
            paths, _ = self.files(Path(temp))
            before = paths[1].read_bytes()
            r = rebuild(Path(temp))
            self.assertFalse(r['applied'])
            self.assertEqual(before, paths[1].read_bytes())

    def test_rebuild_apply_preserves_answers_scores_and_plan_time(self):
        with tempfile.TemporaryDirectory() as temp:
            paths, old = self.files(Path(temp))
            result = rebuild(Path(temp), apply=True)
            new = json.loads(paths[1].read_text())
            self.assertEqual(new['analyses'], old['analyses'])
            self.assertEqual(new['run_time'], old['run_time'])
            self.assertEqual(new['cross_layer_assessment'], old['cross_layer_assessment'])
            self.assertEqual(new['public_associations']['organizations'], ['Apollo Hospitals'])
            self.assertTrue(Path(result['backup']).exists())

    def test_rebuild_refuses_other_run(self):
        with tempfile.TemporaryDirectory() as temp:
            paths, old = self.files(Path(temp))
            old['source_run_id'] = 'OTHER'
            paths[1].write_text(json.dumps(old))
            before = paths[1].read_bytes()
            with self.assertRaisesRegex(ValueError, 'different runs'):
                rebuild(Path(temp), apply=True)
            self.assertEqual(before, paths[1].read_bytes())


if __name__ == '__main__':
    unittest.main()
