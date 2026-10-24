"""Standalone public-repository guard. No private database access or credentials."""
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlparse
from decimal import Decimal
from jsonschema import Draft202012Validator,FormatChecker

PATTERNS=[r'/(?:Users|home|private|var/folders)/',r'[A-Za-z]:\\\\',r'data/private/',r'exports/private/',r'file://',r'(?i)(?:set-cookie|cookie|authorization)\s*:',r'gh[pousr]_[A-Za-z0-9]{20,}',r'github_pat_[A-Za-z0-9_]{20,}',r'(?i)bearer\s+[A-Za-z0-9._~+/-]{12,}',r'(?i)(?:password|session_id|access_token|api_key)\s*[:=]',r'\bsk-[A-Za-z0-9_-]{24,}',r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}',r'<\s*[/!a-zA-Z]']
SOURCE_HOSTS={'www.ttyingqiu.com','www.bbc.com','www.espn.com'}
SITE_FILES={'index.html','styles.css','app.js','stats.js','data/public.json','.nojekyll','release.json'}


def scan_text(text):
    for pattern in PATTERNS:
        if re.search(pattern,text):raise ValueError('Public privacy/content scan rejected sensitive or markup text')


def validate(data,schema):
    errors=list(Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(data))
    if errors:raise ValueError('Public Schema rejected: '+errors[0].message)
    def walk(v,key=''):
        if isinstance(v,dict):
            for k,x in v.items():walk(x,k)
        elif isinstance(v,list):
            for x in v:walk(x,key)
        elif isinstance(v,str):
            scan_text(v)
            if key=='source_url' or key=='source_urls':
                u=urlparse(v)
                if u.scheme!='https' or u.hostname not in SOURCE_HOSTS or u.username or u.password or u.query or u.fragment:raise ValueError('Unapproved public citation URL')
    walk(data)
    expected=hashlib.sha256(json.dumps({k:v for k,v in data.items() if k!='release_id'},sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()).hexdigest()
    if data['release_id']!=expected:raise ValueError('Public release content hash mismatch')
    state=data['status'];context=state.get('deployment_context')
    if context:
        previous=context['previous_verified_release_id'] is not None
        failed=context['latest_attempt_status']=='FAILED'
        expected_state=('PREVIOUS_SUCCESS_LATEST_ATTEMPT_FAILED' if previous else 'LATEST_ATTEMPT_FAILED') if failed else ('PREVIOUS_DEPLOYMENT_VERIFIED' if previous else 'AWAITING_DEPLOYMENT_VERIFICATION')
        if state['publication']!=expected_state:raise ValueError('Publication state contradicts deployment context')
        if previous and (not state['last_success_at'] or not state['last_verified_commit']):raise ValueError('Previous deployment proof missing')
        if failed and not context['latest_failure_code']:raise ValueError('Failure reason missing')
        if not failed and context['latest_failure_code'] is not None:raise ValueError('Failure reason without failed attempt')
    elif state['publication']!='AWAITING_DEPLOYMENT_VERIFICATION':raise ValueError('Legacy snapshot cannot claim new deployment status')
    rows=data['statistics']['rows'];summary=data['statistics']['overall']
    active=[r for r in rows if r['settlement_class']!='VOID']
    if summary['N']!=len(active) or summary['E']!=len([r for r in active if r['settlement_class']!='PUSH']):raise ValueError('Statistics denominator mismatch')
    if Decimal(summary['net_profit'])!=sum((Decimal(r['unit_profit']) for r in active),Decimal(0)):raise ValueError('Per-pick profit mismatch')
    if Decimal(summary['invested_units'])!=len(active):raise ValueError('One-unit accounting mismatch')
    ids=set();official=set();pending_matches=set()
    for f in data['forecasts']:
        if f['forecast_id'] in ids:raise ValueError('Duplicate forecast')
        ids.add(f['forecast_id'])
        if f['publication_status']=='AWAITING_DEPLOYMENT_VERIFICATION':
            if f['match_id'] in pending_matches:raise ValueError('Only one pending version per match per release')
            pending_matches.add(f['match_id'])
        if f['official_eligible']:
            if f['match_id'] in official:raise ValueError('Multiple current official versions')
            official.add(f['match_id'])
            if not f['deployment_verified_at'] or f['deployment_verified_at']>=f['kickoff_utc']:raise ValueError('Official deployment boundary invalid')
        if len(f['picks']) not in (1,2) or [p['tier'] for p in f['picks']].count('FIRST')!=1 or len({p['tier'] for p in f['picks']})!=len(f['picks']):raise ValueError('Invalid pick tiers')
        if any(p['tier']=='SECOND' for p in f['picks']) and not f['analysis']['secondary_value']:raise ValueError('Second pick needs additional-value disclosure')
        for p in f['picks']:
            sides={'1X2':{'HOME','DRAW','AWAY'},'AH':{'HOME','AWAY'},'OU':{'OVER','UNDER'}}
            if p['direction'] not in sides[p['market_type']]:raise ValueError('Wrong market direction')
            if p['market_type']=='1X2' and p['line'] is not None:raise ValueError('1X2 must not have a line')
            if p['market_type']!='1X2':
                if p['line'] is None or Decimal(p['line'])*4!=(Decimal(p['line'])*4).to_integral_value():raise ValueError('Quarter-step line required')
                if p['market_type']=='OU' and Decimal(p['line'])<0:raise ValueError('Negative total')
            if Decimal(p['price'])<=0 or (p['quote_format']=='DECIMAL' and Decimal(p['price'])<=1):raise ValueError('Invalid locked quote')
    for r in rows:
        if r['forecast_id'] not in ids or r['match_id'] not in official:raise ValueError('Statistic has no current official public forecast')
    return True


def check(root):
    root=Path(root);site=root/'site'
    files={p.relative_to(site).as_posix() for p in site.rglob('*') if p.is_file()}
    if files!=SITE_FILES or any(p.is_symlink() for p in root.rglob('*')):raise ValueError('Unexpected artifact file or symlink')
    allowed={'site/'+n for n in SITE_FILES}|{'README.md','.github/workflows/pages.yml','schemas/public.schema.json','scripts/check_public.py','scripts/stats_check.mjs'}
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and '.git' not in p.relative_to(root).parts}
    if actual!=allowed:raise ValueError('Unexpected file in public repository')
    for name in actual:
        value=(root/name).read_bytes()
        if len(value)>8_000_000:raise ValueError('Public asset exceeds explicit 8MB review limit; split before publishing')
        text=value.decode()
        if name=='scripts/check_public.py':text='\n'.join(line for line in text.splitlines() if not line.startswith('PATTERNS='))
        for pattern in PATTERNS[:-1]:
            if re.search(pattern,text):raise ValueError('Repository privacy scan rejected')
    schema=json.loads((root/'schemas/public.schema.json').read_text());data=json.loads((site/'data/public.json').read_text());validate(data,schema)
    manifest=json.loads((site/'release.json').read_text())
    if manifest['release_id']!=data['release_id'] or set(manifest['files'])!=SITE_FILES-{'release.json'}:raise ValueError('Artifact manifest mismatch')
    for name,digest in manifest['files'].items():
        value=(site/name).read_bytes()
        if hashlib.sha256(value).hexdigest()!=digest:raise ValueError('Artifact changed after validation')
        if name.endswith('.json'):continue
        # Static code contains tag syntax; scan only credential/path patterns here.
        text=value.decode()
        for pattern in PATTERNS[:-1]:
            if re.search(pattern,text):raise ValueError('Asset privacy scan rejected')
    return data

if __name__=='__main__':
    import sys
    result=check(Path(sys.argv[1]) if len(sys.argv)>1 else Path.cwd())
    if '--allow-technical-demo' not in sys.argv and result['dataset']!='PRODUCTION':raise SystemExit('Technical demo cannot be deployed')
    print(json.dumps({'status':'PASS','release_id':result['release_id'],'dataset':result['dataset']}))
