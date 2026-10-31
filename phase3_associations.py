"""Local, source-bound professional/academic association extraction.

No API calls and no current-employment inference. A user rejection is a veto.
Entity lists are candidate metadata, NOT evidence of a person's association.
Every displayed value has a short, subject-bound quote from an accepted source.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

VERSION = 8
MAX_ORGANIZATIONS = 4
MAX_ROLES = 6
MAX_ASSOCIATION_ROWS = 3


def clean(value: Any) -> str:
    return ' '.join(html.unescape(str(value or '')).split()).strip(' |,;:')


def decision(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get('response', value.get('decision', value.get('status')))
    if value is True:
        return 'confirmed'
    if value is False:
        return 'rejected'
    value = clean(value).casefold()
    if value in {'no', 'n', 'false', 'rejected', 'reject', 'not_mine', 'not mine'}:
        return 'rejected'
    if value in {'yes', 'y', 'true', 'confirmed', 'accepted'}:
        return 'confirmed'
    if value in {'unsure', 'u', 'unknown', 'uncertain', 'pending', 'unresolved'}:
        return 'unsure'
    if value in {'not_required', 'not required'}:
        return 'not_required'
    return ''


def final_decision(analysis: dict) -> str:
    # The saved human response is authoritative, even over an older visual match
    # or a later AI-produced "confirmed" value. Contradictions fail closed.
    values = [decision(analysis.get('user_verification'))]
    audit = analysis.get('verification_audit') or {}
    if isinstance(audit, dict):
        values.append(decision(audit.get('response')))
    if 'rejected' in values:
        return 'rejected'
    if 'unsure' in values:
        return 'unsure'
    if 'confirmed' in values:
        return 'confirmed'
    return 'not_required' if 'not_required' in values else ''


def source_url(item: dict) -> str:
    return clean(item.get('canonical_url') or item.get('resolved_url') or item.get('url'))


def canonical_url(value: str) -> str:
    """Remove only tracking noise; do not merge different records on one domain."""
    try:
        p = urlsplit(value)
        if p.scheme not in {'http', 'https'} or not p.hostname:
            return ''
        host = p.hostname.lower().removeprefix('www.')
        port = p.port
        if port and port not in {80, 443}:
            host += ':' + str(port)
        query = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
                 if not k.casefold().startswith('utm_') and k.casefold() not in {'fbclid', 'gclid'}]
        # Canonicalize only known YouTube URL forms; video IDs remain distinct.
        if host == 'youtu.be':
            return 'https://youtube.com/watch?' + urlencode({'v': p.path.strip('/')})
        if host in {'youtube.com', 'm.youtube.com'} and p.path == '/watch' and dict(query).get('v'):
            return 'https://youtube.com/watch?' + urlencode({'v': dict(query)['v']})
        return urlunsplit(('https', host, p.path.rstrip('/') or '/', urlencode(sorted(query)), ''))
    except (ValueError, TypeError):
        return ''


def source_binding(report: dict, item: dict) -> dict:
    """Run + URL + content fingerprint; never treated as identity proof."""
    payload = {k: item.get(k) for k in (
        'title', 'snippet', 'identity_status', 'entities', 'published_date',
        'source_date', 'extracted_content', 'association_evidence_text')}
    payload['url'] = canonical_url(source_url(item))
    packed = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return {'version': 1, 'source_run_id': str(report.get('run_id') or ''),
            'fingerprint': hashlib.sha256(packed.encode('utf-8')).hexdigest()}


def bind_compact_sources(report: dict, compact: dict) -> None:
    rows = (report.get('layers', {}).get('phase_2A_public', {}) or {}).get('results', []) or []
    index = {f'P2A-{i:03d}': row for i, row in enumerate(rows, 1)}
    for finding in compact.get('findings', []) or []:
        row = index.get(finding.get('finding_id'))
        if row is not None:
            finding['_local_source_binding'] = source_binding(report, row)


def bound_source_is_valid(report: dict, item: dict, analysis: dict) -> bool:
    binding = analysis.get('source_binding') or analysis.get('_local_source_binding')
    # Legacy records can be rebuilt only against their matching aggregate run.
    # Callers rebuilding a saved file enforce the run ID separately.
    return not binding or binding == source_binding(report, item)


def acceptance(item: dict, analysis: dict) -> tuple[bool, str]:
    answer = final_decision(analysis)
    if answer == 'rejected':
        return False, 'excluded_user_no'
    if answer == 'unsure':
        return False, 'excluded_user_unsure'
    if answer == 'confirmed':
        return True, 'user_yes'
    if not analysis:
        return False, 'excluded_missing_phase3_decision'
    if analysis.get('needs_user_verification'):
        return False, 'excluded_pending_confirmation'
    if answer == 'not_required' and clean(item.get('identity_status')).casefold() == 'confirmed':
        return True, 'deterministic_identity_confirmation'
    visual = item.get('visual_identity') or {}
    if (answer == 'not_required' and
            decision(visual.get('manual_verification_status')) == 'confirmed'):
        return True, 'manual_visual_confirmation_with_subject_text_required'
    return False, 'excluded_unconfirmed'


ALIASES = (
    (re.compile(r"\b(?:svkm['’]s\s+)?narsee\s+monjee\s+institute\s+of\s+management\s+studies\b|\bnmims\b", re.I), 'NMIMS'),
    (re.compile(r'\bmukesh\s+patel\s+school\s+of\s+technology\s+management\s*(?:&|and)\s*engineering\b|\bmpstme\b', re.I), 'MPSTME'),
)
SUFFIX = (r'(?:Company(?:\s+Limited)?|Private\s+Limited|Pvt\.?\s+Ltd\.?|Limited|Ltd\.?|'
          r'Corporation|Corp\.?|Fincorp(?:\s+Limited)?|Finance|Bank|University|College|Academy|'
          r'Group|Technologies|Systems|Labs?|Foundation|Association|Council|Hospitals?|'
          r'Clinic|Healthcare|Medical\s+(?:Centre|Center|Institute))')
TOKEN = r"(?:[A-Z][A-Za-z0-9&'.’-]*|[A-Z]{2,})"
ORG_RE = re.compile(r'\b(' + TOKEN + r'(?:\s+' + TOKEN + r'){0,7}\s+(?i:' + SUFFIX + r'))\b')
# Institution names can START with "University/Institute/... of", rather than
# ending in University. Preserve the observed wording; do not infer an employer
# from a hostname or from a bare institutional acronym.
PREFIX_ORG_RE = re.compile(
    r'\b((?i:University|Institute|School|College)\s+(?i:of)\s+'
    r'(?:(?i:the)\s+)?' + TOKEN +
    r'(?:\s+(?:(?i:of|the|and)\s+|&\s+)?' + TOKEN + r'){0,7})\b')

# Exclude descriptions, navigation, role strings and specialties as organization names.
ORG_NOISE = re.compile(
    r'\b(?:general\s+physician|ent|ob[- ]?gynae|paediatrics|pediatrics|neurology|'
    r'lab\s+tests?|find|book|appointment|designat\w*|comprises|sections?|'
    r'board|business\s+head|chief|executive|vice|president|student|professor|'
    r'bachelor|master|degree|course|top|best|was|were|is|are|has|have|details)\b', re.I)
GENERIC_ORGS = {'college', 'university', 'school', 'institute', 'hospital', 'hospitals',
                'lab', 'labs', 'company', 'limited', 'ltd', 'finance', 'group',
                'medical centre', 'medical center', 'clinic', 'healthcare', 'research'}
NAVIGATION = re.compile(r'general\s+physician|\bent\b|ob[- ]?gynae|paediatrics|pediatrics|'
                        r'neurology|lab\s+tests|find\s+a|book\s+(?:a|an)|'
                        r'privacy\s+policy|terms\s+(?:of|and)|copyright|all\s+rights', re.I)


def canonical_org(value: Any) -> str:
    value = clean(value).strip(' .,-|')
    for pattern, canonical in ALIASES:
        if pattern.fullmatch(value):
            return canonical
    if (not value or len(value) > 95 or len(value.split()) > 10 or
            value.casefold() in GENERIC_ORGS or ORG_NOISE.search(value)):
        return ''
    if PREFIX_ORG_RE.fullmatch(value):
        return value
    if re.search(r'\b(?:at|of|with|from|to)\b', value, re.I):
        # Only explicitly normalized institute aliases are allowed here.
        return ''
    if ORG_RE.fullmatch(value):
        return value
    return ''


def org_mentions(text: str):
    matches = []
    for pattern, label in ALIASES:
        for m in pattern.finditer(text):
            matches.append((label, m.start(), m.end()))
    for m in PREFIX_ORG_RE.finditer(text):
        label = canonical_org(m.group(1))
        if label:
            matches.append((label, m.start(), m.end()))
    for m in ORG_RE.finditer(text):
        if any(m.start() >= a and m.end() <= b for _, a, b in matches):
            continue
        label = canonical_org(m.group(1))
        if label:
            matches.append((label, m.start(), m.end()))
        else:
            # Retry shorter capitalized suffixes after a role/prose prefix.
            fragment = m.group(1)
            for part in re.finditer(r'\S+\s+', fragment):
                candidate = canonical_org(fragment[part.end():])
                if candidate:
                    matches.append((candidate, m.start() + part.end(), m.end()))
                    break
    return matches


ROLE_PATTERNS = (
    (r'\bprofessor\s*\(\s*assistant\s*\)(?!\w)', 'Assistant Professor'),
    (r'\bassistant\s+professor\b', 'Assistant Professor'),
    (r'\bassociate\s+professor\b', 'Associate Professor'),
    (r'\bprofessor\b', 'Professor'),
    (r'\blecturer\b', 'Lecturer'),
    (r'\b(?:senior|sr\.?)\s+consultant\s*[,–—&/\-]?\s*ortho(?:paedic|pedic)s?\b', 'Senior Consultant — Orthopaedics'),
    (r'\bconsultant\s*[,–—&/\-]?\s*ortho(?:paedic|pedic)s?\b', 'Consultant — Orthopaedics'),
    (r'\bortho(?:paedic|pedic)(?:\s+and\s+joint\s+replacement)?\s+surgeon\b', 'Orthopaedic Surgeon'),
    (r'\bjoint\s+replacement\s+surgeon\b', 'Joint Replacement Surgeon'),
    (r'\bortho(?:paedician|pedician|paedist|pedist)\b', 'Orthopaedician'),
    (r'\brobotic\s+surgeon\b', 'Robotic Surgeon'),
    (r'\b(?:senior|sr\.?)\s+consultant\b', 'Senior Consultant'),
    (r'\bconsultant\b', 'Consultant'),
    (r'\b(?:physician|medical\s+doctor)\b', 'Physician'),
    (r'\bchief\s+executive\s+officer\b|\bceo\b', 'Chief Executive Officer'),
    (r'\b(?:senior|sr\.?)\s+vice[- ]+president\b', 'Senior Vice President'),
    (r'\bvice[- ]+president\b|\bvp\b', 'Vice President'),
    (r'\bbusiness\s+head\b', 'Business Head'),
    (r'\bnational\s+sales\s+head\b', 'National Sales Head'),
    (r'\bfounder\b', 'Founder'),
    (r'\bdirector\b', 'Director'),
    (r'\bmanager\b', 'Manager'),
    (r'\bengineer\b', 'Engineer'),
    (r'\bresearch\s+fellow\b', 'Research Fellow'),
    (r'\bresearch\s+scientist\b', 'Research Scientist'),
    (r'\bassociate\s+user\s+researcher\b', 'Associate User Researcher'),
    (r'\b(?:user\s+experience|ux)\s+researcher\b', 'User Experience Researcher'),
    (r'\buser\s+researcher\b', 'User Researcher'),
    (r'\bresearcher\b', 'Researcher'),
    (r'\b(?:user\s+experience|ux)\s+designer\b', 'User Experience Designer'),
    (r'\binteraction\s+designer\b', 'Interaction Designer'),
    (r'\bproduct\s+designer\b', 'Product Designer'),
    (r'\b(?:user\s+experience|ux)\s+design\s+student\b', 'User Experience Design Student'),
    (r'\bdesign\s+student\b', 'Design Student'),
    (r'\bdoctoral\s+student\b|\bph\.?d\.?\s+student\b', 'Doctoral Student'),
    (r'\bpostgraduate\s+student\b', 'Postgraduate Student'),
    (r'\bundergraduate\s+student\b', 'Undergraduate Student'),
    (r'\bstudent\b', 'Student'),
)
ROLES = [(re.compile(p, re.I), label) for p, label in ROLE_PATTERNS]


def subject_pattern(name: str):
    name = re.sub(r'^(?:(?:dr|prof|mr|mrs|ms|professor)\.?\s+)+', '', clean(name), flags=re.I)
    words = re.findall(r'\w+', name, re.UNICODE)
    if not words:
        return None
    return re.compile(r'(?<!\w)' + r'[\s._-]+'.join(map(re.escape, words)) + r'(?!\w)', re.I)


def _sentences(text: str):
    # Do not split after honorifics/legal abbreviations. Body lines stay separate.
    text = html.unescape(str(text or ''))
    for line in text.splitlines():
        protected = re.sub(r'\b(Dr|Prof|Mr|Mrs|Ms|Sr|Jr|Ltd|Pvt)\.', lambda m: m.group(1) + '\x01', line, flags=re.I)
        for value in re.split(r'(?<=[.!?])\s+(?=[A-Z])', protected):
            value = clean(value.replace('\x01', '.'))
            if value:
                yield value


def evidence_units(item: dict, full_name: str):
    """Only a named subject's title, own snippet, or own body sentence."""
    pattern = subject_pattern(full_name)
    if pattern is None:
        return []
    title = clean(item.get('title'))
    has_title = bool(pattern.search(title))
    title_person_first = bool(pattern.match(re.sub(r'^(?:Dr|Prof)\.?\s+', '', title, flags=re.I)))
    structured_profile = has_title and title_person_first and (
        bool(re.search(r'\s[|–—-]\s|\|', title)) or
        'profile' in clean(item.get('source_category')).casefold() or
        bool(re.search(r'/(?:doctor|doctors|in|profile)/', source_url(item))))
    units = []
    if has_title:
        units.append({'field': 'title', 'text': title[:900], 'profile_context': False})
    for field, text in [('snippet', item.get('snippet', '')),
                        ('body', item.get('association_evidence_text') or item.get('extracted_content', ''))]:
        limit = 6000 if field == 'snippet' else 32000
        for sentence in _sentences(str(text or '')[:limit]):
            named = pattern.search(sentence)
            # Never consume page-wide entity metadata or context from a page menu.
            if len(NAVIGATION.findall(sentence)) >= 2:
                if named:
                    sentence = sentence[named.start():]
                if len(NAVIGATION.findall(sentence)) >= 2:
                    continue
            if pattern.search(sentence):
                units.append({'field': field, 'text': sentence[:900], 'profile_context': False})
            elif field == 'snippet' and structured_profile:
                # A profile's role-first subtitle may omit its subject's name.
                beginning = re.sub(r'^(?:he|she)\s+(?:is|was)\s+(?:an?\s+)?', '', sentence, flags=re.I)
                starts_role = any(p.match(beginning) for p, _ in ROLES)
                # Avoid 'Student Ravi Shah...' from a neighboring profile.
                if starts_role and re.search(r'\b(?:at|with|in|of)\b|[|•]', sentence, re.I):
                    units.append({'field': field, 'text': sentence[:900], 'profile_context': True})
    seen = set()
    return [u for u in units if not (u['text'] in seen or seen.add(u['text']))][:30]


ROLE_CONNECTOR = re.compile(
    r"^[\s,|:;–—\-]*(?:(?:is|was|an?|the|works?|worked|working|serves?|served|serving|as|"
    r"appointed|named|became|formerly|previously|retired|acting|currently|now|best|senior|sr\.?|"
    r"consultant|and|orthopaedic|orthopedic|robotic|joint|replacement|surgery|of|in|"
    r"department|\d{4})[\s,|:;–—\-]*)*$", re.I)
RELATION_BREAK = re.compile(r'\b(?:met|invited|introduces?|welcomed|thanks?|thanked|'
                            r'teaches?|students|colleagues?|another|other|read|copyright|'
                            r'privacy|terms|menu|tests|find|book|sponsored|sponsor|publisher)\b', re.I)


def _owned(text: str, start: int, end: int, pattern, kind: str, profile: bool = False, title=False):
    """Require a subject/claim relationship, rather than mere page co-occurrence."""
    positions = list(pattern.finditer(text))
    if profile and not positions:
        # Profile subtitle: role + at organization; reject another named subject.
        if RELATION_BREAK.search(text[:start]):
            return False
        first = next((m for p, _ in ROLES for m in p.finditer(text) if m.start() < 12), None)
        if first is None:
            return False
        # A profile subtitle can say "Design Student at ..." without repeating
        # the subject. "Design Student Ravi Sharma at ..." names somebody else.
        # Validate that distinction BEFORE accepting either the role or employer.
        tail = text[first.end():]
        if not re.match(r'^[\s,–—\-]*(?:(?:at|with|in|of)\b|[|•])', tail, re.I):
            return False
        if kind == 'role':
            return start <= first.end() + 2
        between = text[first.end():start]
        if re.search(r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b', between):
            return False
        return bool(re.search(r'\b(?:at|with|of|in)\s*$', between, re.I))
    for name in positions:
        if start >= name.end():
            between = text[name.end():start]
            if len(between) > 160 or RELATION_BREAK.search(between):
                continue
            if kind == 'role':
                if ROLE_CONNECTOR.fullmatch(between):
                    return True
            else:
                # Separate personal title metadata is valid association evidence.
                if title and re.fullmatch(r'[\s,|:–—\-]+', between):
                    return True
                if re.search(r'\b(?:at|with|from|of|joined|joining|attended|associated\s+with|'
                             r'graduated\s+from|studied\s+at|affiliated\s+with)\s*$', between, re.I):
                    # Do not assign an employer of an intervening named person.
                    without_roles = between
                    for p, _ in ROLES:
                        without_roles = p.sub('', without_roles)
                    if not re.search(r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b', without_roles):
                        return True
                if title and ('|' in between or ' - ' in between or '—' in between):
                    # Permit degree/role segments in the person's own profile title.
                    if not re.search(r'\b(?:by|for|thanks|sponsor|award|another)\b', between, re.I):
                        return True
        elif end <= name.start():
            between = text[end:name.start()]
            if len(between) > 110 or RELATION_BREAK.search(between):
                continue
            if kind == 'role' and re.fullmatch(r'[\s,|:–—\-]*(?:(?:Dr|Prof)\.?\s*)?', between, re.I):
                return True
            if kind == 'organization' and re.fullmatch(
                    r'[\s,:–—\-]*(?:appoints?|appointed|names?|named|welcomes?|employs?)\s*', between, re.I):
                return True
    return False


def extract_claims(item: dict, full_name: str):
    pattern = subject_pattern(full_name)
    if pattern is None:
        return []
    claims = []
    seen = set()
    for unit in evidence_units(item, full_name):
        text = unit['text']
        # One specific role per overlapping span (Assistant Professor != Professor).
        covered = []
        mentions = []
        for regex, label in ROLES:
            for m in regex.finditer(text):
                if any(m.start() < b and m.end() > a for a, b in covered):
                    continue
                if _owned(text, m.start(), m.end(), pattern, 'role', unit['profile_context'], unit['field'] == 'title'):
                    covered.append((m.start(), m.end()))
                    mentions.append(('role', label, m.start(), m.end()))
        for label, start, end in org_mentions(text):
            if _owned(text, start, end, pattern, 'organization', unit['profile_context'], unit['field'] == 'title'):
                mentions.append(('organization', label, start, end))
        for kind, value, start, end in mentions:
            if (kind, value.casefold()) not in seen:
                seen.add((kind, value.casefold()))
                claims.append({'kind': kind, 'value': value, 'source_field': unit['field'],
                               'evidence_excerpt': text, 'claim_start': start, 'claim_end': end,
                               'method': 'subject_linked_text'})
    return claims


def _org_key(value: str) -> str:
    words = re.findall(r'[a-z0-9]+', value.casefold())
    while words and words[-1] in {'limited', 'ltd', 'private', 'pvt', 'company', 'corp', 'corporation'}:
        words.pop()
    if words and words[-1] in {'hospitals', 'clinics'}:
        words[-1] = words[-1][:-1]
    return ' '.join(words)


def _source_date(item: dict) -> str:
    # Retrieval dates are never used as publication/evidence dates.
    raw = clean(item.get('published_date') or item.get('source_date'))
    if not raw:
        return ''
    try:
        d = datetime.fromisoformat(raw.replace('Z', '+00:00'))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        if d > datetime.now(timezone.utc):
            return ''
        return raw
    except ValueError:
        return ''


def _redact_quote(text: str, profile: dict) -> str:
    text = re.sub(r'\b[^\s<>@]+@[^\s<>@]+\.[A-Za-z]{2,}\b', '[email redacted]', text)
    for key in ('email', 'phone'):
        value = str(profile.get(key) or '')
        if value:
            text = re.sub(re.escape(value), '[redacted]', text, flags=re.I)
    return text


def _role_rank(value: str) -> int:
    for index, (_, label) in enumerate(ROLES):
        if label == value:
            return index
    return len(ROLES) + 100


def _pair_distance(role_claim: dict, org_claim: dict) -> int:
    """Distance between two claims in one evidence excerpt."""
    rs, re_ = int(role_claim.get('claim_start', 0)), int(role_claim.get('claim_end', 0))
    os, oe = int(org_claim.get('claim_start', 0)), int(org_claim.get('claim_end', 0))
    if re_ <= os:
        return os - re_
    if oe <= rs:
        return rs - oe
    return 0


def _build_association_rows(claims: list[dict], canonical_display: dict[str, str],
                            allowed_roles: list[str]) -> list[dict]:
    """Build up to three organization→role rows from the SAME accepted source.

    A row is never produced by joining an organization from one source to a role
    from another. Strongest evidence is a role and organization in the same
    subject-linked title/snippet/body sentence. A conservative fallback is used
    only when one accepted source contains exactly one organization and one role.
    """
    allowed = set(allowed_roles)
    by_source = defaultdict(list)
    for claim in claims:
        by_source[claim.get('finding_id', '')].append(claim)

    rows: dict[tuple[str, str], dict] = {}

    def add(org_claim: dict, role_claim: dict, finding_id: str, method: str, distance: int):
        org_key = _org_key(org_claim.get('value', ''))
        role = role_claim.get('value', '')
        organization = canonical_display.get(org_key, org_claim.get('value', ''))
        if not org_key or not organization or role not in allowed:
            return
        key = (org_key, role)
        row = rows.setdefault(key, {
            'organization': organization,
            'role': role,
            'finding_ids': set(),
            'same_excerpt_sources': set(),
            'fallback_sources': set(),
            'best_distance': 10**9,
            'evidence_excerpt': '',
        })
        row['finding_ids'].add(finding_id)
        if method == 'same_excerpt':
            row['same_excerpt_sources'].add(finding_id)
        else:
            row['fallback_sources'].add(finding_id)
        if distance < row['best_distance']:
            row['best_distance'] = distance
            row['evidence_excerpt'] = role_claim.get('evidence_excerpt') or org_claim.get('evidence_excerpt') or ''

    for finding_id, source_claims in by_source.items():
        # First pair claims that occur in the exact same subject-linked evidence unit.
        units = defaultdict(list)
        for claim in source_claims:
            units[(claim.get('source_field', ''), claim.get('evidence_excerpt', ''))].append(claim)
        paired_this_source = False
        for unit_claims in units.values():
            orgs = [c for c in unit_claims if c.get('kind') == 'organization']
            roles = [c for c in unit_claims if c.get('kind') == 'role' and c.get('value') in allowed]
            if not orgs or not roles:
                continue
            # Pair each role only with its nearest organization in the same sentence/title.
            # This avoids cross-products when one sentence names more than one employer.
            for role_claim in roles:
                ranked = sorted(((_pair_distance(role_claim, org), org) for org in orgs), key=lambda x: x[0])
                if not ranked:
                    continue
                distance, org_claim = ranked[0]
                if distance <= 180:
                    add(org_claim, role_claim, finding_id, 'same_excerpt', distance)
                    paired_this_source = True

        # Conservative fallback: same accepted source, one unambiguous role and
        # one unambiguous organization. Claims may occur in different subject-
        # linked excerpts of the SAME source (for example, organization in a
        # profile title and role in its subtitle/body).
        #
        # A known parent/constituent pair such as NMIMS + MPSTME is treated as
        # one affiliation context and the more specific organization (MPSTME)
        # is preferred. Unrelated multi-organization pages remain unpaired.
        if not paired_this_source:
            unique_orgs = {}
            unique_roles = {}
            for claim in source_claims:
                if claim.get('kind') == 'organization':
                    key = _org_key(claim.get('value', ''))
                    if key:
                        unique_orgs.setdefault(key, claim)
                elif claim.get('kind') == 'role' and claim.get('value') in allowed:
                    unique_roles.setdefault(claim.get('value'), claim)

            selected_org = None
            if len(unique_orgs) == 1:
                selected_org = next(iter(unique_orgs.values()))
            elif set(unique_orgs).issuperset({'nmims', 'mpstme'}) and len(unique_orgs) == 2:
                # MPSTME is the more specific unit; do not duplicate the same
                # role once for the school and once for the parent university.
                selected_org = unique_orgs['mpstme']

            if selected_org is not None and len(unique_roles) == 1:
                role_claim = next(iter(unique_roles.values()))
                add(selected_org, role_claim, finding_id, 'same_source_singletons', 999)

    ranked_rows = sorted(
        rows.values(),
        key=lambda r: (
            -len(r['finding_ids']),
            -len(r['same_excerpt_sources']),
            r['best_distance'],
            _role_rank(r['role']),
            r['organization'].casefold(),
        ),
    )[:MAX_ASSOCIATION_ROWS]

    output = []
    for row in ranked_rows:
        output.append({
            'organization': row['organization'],
            'role': row['role'],
            'support_count': len(row['finding_ids']),
            'finding_ids': sorted(row['finding_ids']),
            'pairing_basis': 'same_subject_linked_text' if row['same_excerpt_sources'] else 'same_accepted_source',
            'evidence_excerpt': row['evidence_excerpt'],
        })
    return output


def build_public_associations(report: dict, analyses: list[dict]) -> dict:
    results = (report.get('layers', {}).get('phase_2A_public', {}) or {}).get('results', []) or []
    profile = report.get('input_profile') or {}
    name = clean(profile.get('full_name'))
    am = {}
    duplicate_ids = set()
    for row in analyses or []:
        fid = row.get('finding_id')
        if fid in am:
            duplicate_ids.add(fid)
        am[fid] = row
    # A No applies to duplicate copies of the same canonical page as well.
    blocked_urls = set()
    for i, row in enumerate(results, 1):
        a = am.get(f'P2A-{i:03d}', {})
        if final_decision(a) in {'rejected', 'unsure'} and canonical_url(source_url(row)):
            blocked_urls.add(canonical_url(source_url(row)))

    evidence, audit, claims = [], [], []
    source_seen = set()
    for i, item in enumerate(results, 1):
        fid = f'P2A-{i:03d}'
        a = am.get(fid, {})
        ok, reason = acceptance(item, a)
        url = canonical_url(source_url(item))
        if fid in duplicate_ids:
            ok, reason = False, 'excluded_duplicate_finding_id'
        elif not bound_source_is_valid(report, item, a):
            ok, reason = False, 'excluded_source_changed_restart_phase3'
        elif ok and url and url in blocked_urls:
            ok, reason = False, 'excluded_duplicate_source_has_no_or_unsure'
        saved_audit = a.get('verification_audit') or {}
        if not isinstance(saved_audit, dict):
            saved_audit = {}
        decision_fields = {
            'user_verification': decision(a.get('user_verification')) or 'missing',
            'verification_audit_response': decision(saved_audit.get('response')) or 'missing',
        }
        explicit = {v for v in decision_fields.values()
                    if v in {'confirmed', 'rejected', 'unsure'}}
        entry = {'finding_id': fid, 'title': clean(item.get('title')),
                 'user_decision': final_decision(a) or 'missing', 'accepted': ok,
                 'reason': reason, 'contributed': False,
                 'decision_fields': decision_fields, 'decision_conflict': len(explicit) > 1,
                 'binding_checked': bool(a.get('source_binding') or a.get('_local_source_binding'))}
        audit.append(entry)
        if not ok:
            continue
        found = extract_claims(item, name)
        # Deduplicate source votes without dropping its decision from the audit.
        source_key = url or fid
        if source_key in source_seen:
            entry['reason'] = 'accepted_duplicate_source_not_counted_twice'
            continue
        source_seen.add(source_key)
        if not found:
            entry['reason'] = 'accepted_no_subject_linked_association_found'
            continue
        entry['contributed'] = True
        date = _source_date(item)
        for claim in found:
            claim.update({'finding_id': fid, 'domain': urlsplit(url).netloc if url else '',
                          'published_date': date,
                          'evidence_excerpt': _redact_quote(claim['evidence_excerpt'], profile)})
        claims.extend(found)
        evidence.append({'finding_id': fid, 'title': clean(item.get('title')),
                         'domain': urlsplit(url).netloc if url else '',
                         'source_category': item.get('source_category', ''),
                         'published_date': date, 'acceptance_basis': reason,
                         'user_decision': entry['user_decision'],
                         'organizations': [c['value'] for c in found if c['kind'] == 'organization'],
                         'roles': [c['value'] for c in found if c['kind'] == 'role'],
                         'claims': found})
    org_groups = {}
    role_sources = defaultdict(set)
    for c in claims:
        if c['kind'] == 'organization':
            key = _org_key(c['value'])
            group = org_groups.setdefault(key, {'value': c['value'], 'sources': set()})
            group['sources'].add(c['finding_id'])
            if len(c['value']) > len(group['value']):
                group['value'] = c['value']
        else:
            role_sources[c['value']].add(c['finding_id'])
    organizations = [g['value'] for g in sorted(org_groups.values(), key=lambda g: -len(g['sources']))][:4]
    roles = sorted(role_sources, key=lambda x: (-len(role_sources[x]), next(i for i, (_, v) in enumerate(ROLES) if v == x)))
    # Remove redundant general labels, not genuine historical roles.
    superseded = set()
    if any(x in roles for x in ('Assistant Professor', 'Associate Professor')):
        superseded.add('Professor')
    if 'Senior Vice President' in roles:
        superseded.add('Vice President')
    if 'Senior Consultant — Orthopaedics' in roles:
        superseded.update({'Consultant', 'Senior Consultant', 'Consultant — Orthopaedics'})
    elif 'Consultant — Orthopaedics' in roles or 'Senior Consultant' in roles:
        superseded.add('Consultant')
    if any(x in roles for x in ('Design Student', 'User Experience Design Student',
                                'Undergraduate Student', 'Postgraduate Student', 'Doctoral Student')):
        superseded.add('Student')
    if 'User Experience Design Student' in roles:
        superseded.add('Design Student')
    if any(x in roles for x in ('Associate User Researcher', 'User Experience Researcher', 'User Researcher')):
        superseded.add('Researcher')
    if 'Associate User Researcher' in roles:
        superseded.add('User Researcher')
    roles = [r for r in roles if r not in superseded][:MAX_ROLES]
    displayed_claims = [c for c in claims if (
        c['kind'] == 'organization' and _org_key(c['value']) in {_org_key(v) for v in organizations})
        or (c['kind'] == 'role' and c['value'] in roles)]
    canonical_display = {_org_key(g['value']): g['value'] for g in org_groups.values()}
    association_rows = _build_association_rows(claims, canonical_display, roles)
    displayed_claims = [dict(c, value=canonical_display.get(_org_key(c['value']), c['value']),
                             extracted_value=c['value'])
                        if c['kind'] == 'organization' else c for c in displayed_claims]
    dates = sum(bool(e['published_date']) for e in evidence)
    counts = Counter(e['user_decision'] for e in audit)
    included = sum(e['accepted'] for e in audit)
    recency = ('No supported association evidence' if not evidence else
               'Mostly undated' if not dates else
               'Dated evidence available' if dates == len(evidence) else 'Mixed / mostly undated')
    # Confidence is a rule-based evidence-strength label, NOT a calibrated probability.
    support = max([len(g['sources']) for g in org_groups.values()] +
                  [len(s) for s in role_sources.values()] + [0])
    confidence = 'Medium' if support >= 2 else 'Low'
    warnings = []
    if any(e['accepted'] and not e['binding_checked'] for e in audit):
        warnings.append('Legacy decisions have no per-source fingerprint. Check the decision audit before relying on this rebuilt summary.')
    conflicts = [e['finding_id'] for e in audit if e['decision_conflict']]
    if conflicts:
        warnings.append('Saved decision fields disagree for: ' + ', '.join(conflicts) +
                        '. No/Unsure remains a veto; the repair did not change either saved field.')
    return {'schema_version': VERSION, 'source_run_id': report.get('run_id'),
            'organizations': organizations, 'roles': roles, 'association_rows': association_rows, 'confidence': confidence,
            'confidence_basis': 'Rule-based support for the displayed associations, not a probability or current-status claim.',
            'evidence_recency': recency,
            'summary': ('Only accepted findings with subject-linked evidence contribute below. '
                        'No and Unsure findings are excluded. Up to three organization-role pairs are shown '
                        'only when both are supported by the same accepted source; no current status is inferred.'),
            'evidence': evidence, 'claims': displayed_claims,
            'verified_evidence_count': len(evidence), 'dated_evidence_count': dates,
            'source_audit': audit,
            'source_counts': {'public_findings': len(results), 'user_yes': counts.get('confirmed', 0),
                              'user_no': counts.get('rejected', 0), 'user_unsure': counts.get('unsure', 0),
                              'accepted_sources': included, 'excluded_sources': len(audit) - included,
                              'contributing_sources': len(evidence),
                              'accepted_without_new_claim': included - len(evidence)},
            'warnings': warnings}
