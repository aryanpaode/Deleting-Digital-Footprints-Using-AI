"""Offline regressions for accepted-source extraction and decision transparency.

An anonymized synthetic fixture reproduces the decision-count distribution and
association-extraction patterns. No real scan reports or network services are used.
"""
import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import phase3_associations as pa
from repair_phase3_associations import rebuild, main

NAME = 'Maya Mehra'


def row(title, **kw):
    item = {'title': title, 'snippet': '', 'source_category': 'Academic profile',
            'identity_status': 'Possible', 'url': 'https://example.org/profile/one'}
    item.update(kw)
    return item


def source(rows, name=NAME):
    return {'artifact_type': 'aggregated_footprint_report', 'run_id': 'OFFLINE-RECALL-TEST',
            'input_profile': {'full_name': name},
            'layers': {'phase_2A_public': {'results': rows}}}


def decisions(values):
    return [{'finding_id': f'P2A-{i:03d}', 'user_verification': v,
             'verification_audit': {'response': v},
             'needs_user_verification': v == 'unsure'} for i, v in enumerate(values, 1)]


def build(titles, values=None, name=NAME):
    rows = [row(t, url=f'https://example.org/profile/{i}') for i, t in enumerate(titles)]
    return pa.build_public_associations(source(rows, name), decisions(values or ['confirmed'] * len(rows)))


class AcceptedEvidenceRecallTests(unittest.TestCase):
    def test_design_student_is_a_complete_subject_role(self):
        title = 'Maya Mehra - Design Student in Mumbai, India'
        result = build([title])
        self.assertEqual(result['roles'], ['Design Student'])
        self.assertEqual(result['organizations'], [])
        self.assertEqual(result['claims'][0]['evidence_excerpt'], title)

    def test_prefix_style_university_name_preserved(self):
        result = build(['Maya MEHRA | University of the Arts London'])
        self.assertEqual(result['organizations'], ['University of the Arts London'])
        self.assertEqual(result['roles'], [])

    def test_title_prefix_rule_is_not_person_specific(self):
        result = build(['Example Person | University of Northbridge'], name='Example Person')
        self.assertEqual(result['organizations'], ['University of Northbridge'])

    def test_design_student_rule_is_not_person_specific(self):
        result = build(['Example Person — Design Student'], name='Example Person')
        self.assertEqual(result['roles'], ['Design Student'])

    def test_institution_does_not_infer_enrolment(self):
        result = build(['Maya Mehra | Institute of Advanced Studies'])
        self.assertEqual(result['organizations'], ['Institute of Advanced Studies'])
        self.assertEqual(result['roles'], [])

    def test_person_discussing_university_is_not_affiliation(self):
        result = build(['Maya Mehra discusses University of the Arts London'])
        self.assertEqual(result['organizations'], [])

    def test_no_still_excludes_recognizable_title(self):
        result = build(['Maya Mehra | Design Student | University of the Arts London'], ['rejected'])
        self.assertEqual(result['organizations'], [])
        self.assertEqual(result['roles'], [])
        self.assertFalse(result['source_audit'][0]['accepted'])

    def test_unsure_still_excludes_recognizable_role(self):
        result = build(['Maya Mehra - Associate User Researcher at NHS England ...'], ['unsure'])
        self.assertEqual(result['roles'], [])
        self.assertEqual(result['source_audit'][0]['reason'], 'excluded_user_unsure')

    def test_accepted_researcher_title_is_parsed_only_if_yes(self):
        result = build(['Maya Mehra - Associate User Researcher at NHS England ...'])
        self.assertEqual(result['roles'], ['Associate User Researcher'])
        # No organization invented from the role or a guessed employer alias.
        self.assertEqual(result['organizations'], [])

    def test_ux_article_topic_does_not_invent_job(self):
        result = build(['Colour and interaction design - by Maya Mehra'])
        self.assertTrue(result['source_audit'][0]['accepted'])
        self.assertFalse(result['source_audit'][0]['contributed'])
        self.assertEqual(result['roles'], [])

    def test_no_inference_from_unnamed_student_directory(self):
        result = build(['All Students - MA User Experience Design - MAUX'])
        self.assertEqual(result['roles'], [])
        self.assertTrue(result['source_audit'][0]['accepted'])

    def test_unknown_bare_acronym_title_not_person_affiliation(self):
        result = build(['UAL'])
        self.assertEqual(result['organizations'], [])

    def test_role_in_other_person_interview_not_assigned(self):
        result = build(["Maya Mehra's interview with a Design Student"])
        self.assertEqual(result['roles'], [])

    def test_role_first_own_profile_subtitle(self):
        r = source([row('Maya Mehra | Profile', snippet='Design Student at University of the Arts London.')])
        result = pa.build_public_associations(r, decisions(['confirmed']))
        self.assertEqual(result['roles'], ['Design Student'])
        self.assertEqual(result['organizations'], ['University of the Arts London'])

    def test_role_first_subtitle_naming_someone_else_excluded(self):
        r = source([row('Maya Mehra | Profile', snippet='Design Student Ravi Sharma at Oxford University.')])
        result = pa.build_public_associations(r, decisions(['confirmed']))
        self.assertEqual(result['roles'], [])
        self.assertEqual(result['organizations'], [])

    def test_apollo_singular_plural_is_one_organization(self):
        result = build(['Karan Mehra — Apollo hospital', 'Karan Mehra — Apollo Hospitals'], name='Karan Mehra')
        self.assertEqual(result['organizations'], ['Apollo Hospitals'])
        self.assertTrue(all(c['value'] == 'Apollo Hospitals' for c in result['claims']))
        self.assertEqual({c['extracted_value'] for c in result['claims']}, {'Apollo hospital', 'Apollo Hospitals'})

    def test_separate_hospitals_do_not_merge(self):
        result = build(['Karan Mehra | Apollo Hospitals', 'Karan Mehra | Example Hospitals'], name='Karan Mehra')
        self.assertEqual(set(result['organizations']), {'Apollo Hospitals', 'Example Hospitals'})

    def test_generic_and_menu_names_still_rejected(self):
        for value in ['college', 'a top engineering college in Mumbai was',
                      'General Physician ENT Ob-Gynae Paediatrics Neurology Lab Tests Find a',
                      'Bachelor of Technology', 'University of the students']:
            with self.subTest(value=value):
                self.assertEqual(pa.canonical_org(value), '')

    def test_missing_claim_does_not_change_saved_yes(self):
        report = source([row("Maya Mehra's dance recital")])
        saved = decisions(['confirmed'])
        original = copy.deepcopy(saved)
        result = pa.build_public_associations(report, saved)
        self.assertEqual(saved, original)
        self.assertTrue(result['source_audit'][0]['accepted'])
        self.assertFalse(result['source_audit'][0]['contributed'])
        self.assertEqual(result['source_audit'][0]['user_decision'], 'confirmed')

    def test_decision_fields_are_visible_without_mutation(self):
        saved = decisions(['unsure'])
        original = copy.deepcopy(saved)
        result = pa.build_public_associations(source([row('Maya Mehra')]), saved)
        self.assertEqual(result['source_audit'][0]['decision_fields'], {
            'user_verification': 'unsure', 'verification_audit_response': 'unsure'})
        self.assertFalse(result['source_audit'][0]['decision_conflict'])
        self.assertEqual(saved, original)

    def test_conflict_is_explained_and_not_auto_promoted(self):
        saved = decisions(['confirmed'])
        saved[0]['verification_audit']['response'] = 'unsure'
        result = pa.build_public_associations(source([row('Maya Mehra - Design Student')]), saved)
        self.assertEqual(result['roles'], [])
        self.assertTrue(result['source_audit'][0]['decision_conflict'])
        self.assertTrue(any('disagree' in w for w in result['warnings']))
        self.assertEqual(saved[0]['user_verification'], 'confirmed')
        self.assertEqual(saved[0]['verification_audit']['response'], 'unsure')

    def incident_fixture(self):
        # Synthetic titles and representative decision distribution; snippets absent.
        titles = [
            "Maya Mehra's dance recital",
            'Maya Mehra Narsee Monjee Institute of Management Studies',
            'Maya Mehra - Design Student in Mumbai, India',
            'Maya Mehra - Associate User Researcher at NHS England ...',
            'Maya Mehra – Medium', 'Campus event | Maya Mehra | comments',
            'Design journal • Week 1 | by Maya Mehra', "Maya Mehra's Post",
            'Maya Mehra', 'Colour and interaction design - by Maya Mehra',
            'Maya MEHRA | University of the Arts London', 'Designing exit flows - by Maya Mehra',
            'The Design Project - by Maya Mehra', 'All Students - MA User Experience Design - MAUX',
            'Maya Mehra', 'Student exhibition', 'Photographs from an annual sports day',
            'Example International School - North Campus', 'Example International School - South Campus',
            "Annual sports meet - Example School", 'Nina Roy (@ninaroytest) / ...',
            'Nina Roy (@ninaroytest) / ...', 'UAL']
        values = ['confirmed'] * len(titles)
        for n in [4, 16, 17, 18, 19]:
            values[n - 1] = 'unsure'
        for n in [20, 21, 22]:
            values[n - 1] = 'rejected'
        rows = [row(t, url=f'https://example.org/profile/{i}') for i, t in enumerate(titles, 1)]
        return source(rows), decisions(values)

    def test_incident_titles_keep_15_yes_and_recover_two_missing_claims(self):
        r, saved = self.incident_fixture()
        result = pa.build_public_associations(r, saved)
        self.assertEqual(result['source_counts'], {
            'public_findings': 23, 'user_yes': 15, 'user_no': 3, 'user_unsure': 5,
            'accepted_sources': 15, 'excluded_sources': 8,
            'contributing_sources': 3, 'accepted_without_new_claim': 12})
        self.assertEqual(set(result['organizations']), {'NMIMS', 'University of the Arts London'})
        self.assertEqual(result['roles'], ['Design Student'])
        self.assertFalse(result['source_audit'][3]['accepted'])

    def test_apply_does_not_touch_verification_risk_or_phase4(self):
        report, saved_answers = self.incident_fixture()
        saved = {'artifact_type': 'phase3_ai_analysis', 'source_run_id': report['run_id'],
                 'run_time': 'UNCHANGED', 'analyses': saved_answers,
                 'cross_layer_assessment': {'overall_risk_score': 17},
                 'public_associations': {'organizations': ['OLD']}}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = [root / 'reports/aggregate/latest_aggregate_internal.json',
                     root / 'reports/phase3/latest_phase3_analysis.json',
                     root / 'reports/phase4/latest_phase4_state.json']
            for path, data in zip(paths, [report, saved, {'opaque_phase4_state': True}]):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(data), encoding='utf-8')
            phase4_bytes = paths[2].read_bytes()
            original = paths[1].read_bytes()
            result = rebuild(root, apply=True)
            updated = json.loads(paths[1].read_text(encoding='utf-8'))
            self.assertEqual(updated['analyses'], saved['analyses'])
            self.assertEqual(updated['cross_layer_assessment'], saved['cross_layer_assessment'])
            self.assertEqual(updated['run_time'], saved['run_time'])
            self.assertEqual(paths[2].read_bytes(), phase4_bytes)
            self.assertEqual(Path(result['backup']).read_bytes(), original)
            self.assertEqual(updated['public_associations']['roles'], ['Design Student'])

    def test_repair_prints_both_acceptance_and_contribution(self):
        result = pa.build_public_associations(source([row('Maya Mehra')]), decisions(['confirmed']))
        fake = dict(result, applied=False)
        stream = io.StringIO()
        with patch('repair_phase3_associations.rebuild', return_value=fake), \
             patch('sys.argv', ['repair_phase3_associations.py']), redirect_stdout(stream):
            self.assertEqual(main(), 0)
        self.assertIn('accepted=True | association_evidence=False', stream.getvalue())
        self.assertNotIn('| used=False', stream.getvalue())


class OrganizationRolePairingTests(unittest.TestCase):
    def test_same_title_pairs_org_and_role(self):
        result = build(['Rohan Malhotra - Sr Vice President at Magma Fincorp Ltd.'], name='Rohan Malhotra')
        self.assertEqual(result['association_rows'][0]['organization'], 'Magma Fincorp Ltd')
        self.assertEqual(result['association_rows'][0]['role'], 'Senior Vice President')

    def test_appointment_title_pairs_employer_and_role(self):
        result = build(['Shriram Equipment Finance Company Limited appoints Rohan Malhotra as CEO'], name='Rohan Malhotra')
        self.assertEqual(len(result['association_rows']), 1)
        self.assertEqual(result['association_rows'][0]['organization'], 'Shriram Equipment Finance Company Limited')
        self.assertEqual(result['association_rows'][0]['role'], 'Chief Executive Officer')


    def test_appointment_title_without_legal_suffix_pairs_employer_and_role(self):
        result = build(['Shriram Equipment Finance appoints Rohan Malhotra as CEO'], name='Rohan Malhotra')
        self.assertEqual(len(result['association_rows']), 1)
        self.assertEqual(result['association_rows'][0]['organization'], 'Shriram Equipment Finance')
        self.assertEqual(result['association_rows'][0]['role'], 'Chief Executive Officer')

    def test_never_pairs_across_different_sources(self):
        titles = ['Rohan Malhotra | Magma Fincorp Ltd.', 'Rohan Malhotra - Senior Vice President']
        result = build(titles, name='Rohan Malhotra')
        self.assertEqual(result['association_rows'], [])

    def test_rows_are_capped_at_three(self):
        titles = [
            'Example Person | Assistant Professor at Northbridge University',
            'Example Person | Researcher at Example Labs',
            'Example Person | Director at Alpha Technologies',
            'Example Person | Manager at Beta Systems',
        ]
        result = build(titles, name='Example Person')
        self.assertEqual(len(result['association_rows']), 3)


    def test_faculty_profile_pairs_specific_school_with_role_across_same_source_excerpts(self):
        report = source([row(
            'Prof. Kiran Shah - MPSTME - example.org',
            snippet='Kiran Shah is an Assistant Professor.',
            url='https://example.org/faculty/kiran-shah',
        )], name='Kiran Shah')
        result = pa.build_public_associations(report, decisions(['confirmed']))
        self.assertEqual(len(result['association_rows']), 1)
        self.assertEqual(result['association_rows'][0]['organization'], 'MPSTME')
        self.assertEqual(result['association_rows'][0]['role'], 'Assistant Professor')
        self.assertEqual(result['association_rows'][0]['pairing_basis'], 'same_accepted_source')

    def test_professor_assistant_word_order_normalizes_to_assistant_professor(self):
        result = build(
            ['Kiran Shah | Professor (Assistant) | NMIMS'],
            name='Kiran Shah',
        )
        self.assertEqual(result['roles'], ['Assistant Professor'])
        self.assertEqual(len(result['association_rows']), 1)
        self.assertEqual(result['association_rows'][0]['organization'], 'NMIMS')
        self.assertEqual(result['association_rows'][0]['role'], 'Assistant Professor')

    def test_no_and_unsure_never_create_rows(self):
        titles = ['Example Person | Director at Alpha Technologies',
                  'Example Person | Manager at Beta Systems']
        result = build(titles, ['rejected', 'unsure'], name='Example Person')
        self.assertEqual(result['association_rows'], [])


if __name__ == '__main__':
    unittest.main()
