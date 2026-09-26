"""Bounded investigation planner with server-enforced tool capabilities."""
import json
import time
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .policy import redact, suspicious


class ToolCall(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: Literal['search_logs', 'get_asset', 'lookup_indicator']
    asset_id: str = Field(pattern=r'^[a-zA-Z0-9-]{1,64}$')


def call_tool(store, user, raw):
    try:
        call = ToolCall.model_validate(raw)
    except ValidationError as exc:
        store.audit(user, 'tool', outcome='denied')
        raise HTTPException(403, 'Unknown tool or invalid arguments') from exc
    asset = store.one('SELECT * FROM records WHERE id=? AND tenant=? AND kind=?',
                      (call.asset_id, user['tenant'], 'asset'))
    if not asset:
        store.audit(user, 'tool', outcome='denied')
        raise HTTPException(404, 'Asset not found')
    if call.name == 'get_asset':
        result = json.loads(asset['body'])
    elif call.name == 'search_logs':
        result = [r for r in store.records(user['tenant'], 'event') if r['asset_id'] == call.asset_id]
    else:
        result = {'asset_id': call.asset_id, 'source': 'synthetic local intelligence',
                  'known_bad': json.loads(asset['body']).get('known_bad', False)}
    store.audit(user, 'tool.' + call.name, call.asset_id)
    return result


def investigate(store, user, alert_id, model):
    alert = store.record(user['tenant'], 'alert', alert_id)
    if not alert:
        raise HTTPException(404, 'Alert not found')
    trace, evidence = [], []
    start = time.monotonic()
    # Deterministic plan, bounded to three read-only capabilities. A model cannot extend it.
    for name in ['get_asset', 'search_logs', 'lookup_indicator']:
        if time.monotonic() - start > 10:
            raise HTTPException(504, 'Investigation time budget exceeded')
        result = call_tool(store, user, {'name': name, 'asset_id': alert['asset_id']})
        trace.append({'step': len(trace) + 1, 'tool': name, 'status': 'allowed', 'asset_id': alert['asset_id']})
        evidence.append({'title': name, 'body': redact(json.dumps(result))})
    events = json.loads(evidence[1]['body'])
    failed = sum(e['event_type'] == 'login_failed' for e in events)
    succeeded = any(e['event_type'] == 'login_success' for e in events)
    flagged = any(suspicious(e.get('message', '')) for e in events)
    # Use structured telemetry for decisions; log message prose never grants permissions.
    severity = 'high' if failed >= 5 and succeeded else 'medium' if failed >= 5 else 'low'
    facts = f'{failed} failed logins; successful login observed: {succeeded}. Severity: {severity}.'
    summary = facts
    mode = 'rule-based'
    if model.mode == 'ollama':
        # Strip untrusted free-form log messages from evidence provided to the model.
        safe_events = [{k: v for k, v in e.items() if k in {'id','event_type','timestamp','asset_id'}} for e in events]
        generated = model.generate('Summarize this incident. Do not recommend executing commands.',
                                   [{'title': 'Telemetry', 'body': json.dumps(safe_events)},
                                    {'title': 'Rule result', 'body': facts}])
        summary = redact(generated['answer'])
        mode = 'ollama'
    report = {'alert_id': alert_id, 'asset_id': alert['asset_id'], 'severity': severity,
              'summary': summary, 'facts': facts, 'mode': mode, 'trace': trace,
              'timeline': sorted(events, key=lambda e: e['timestamp']),
              'untrusted_instruction_detected': flagged, 'action': 'propose_simulated_isolation' if severity == 'high' else 'review',
              'limitations': 'Synthetic telemetry. Rule-based severity; generated narrative may be inaccurate.'}
    record_id = store.save(user['tenant'], 'investigation', report)
    store.audit(user, 'investigation.create', record_id)
    return dict(id=record_id, **report)


def propose(store, user, report_id):
    report = store.record(user['tenant'], 'investigation', report_id)
    if not report:
        raise HTTPException(404, 'Investigation not found')
    if report['severity'] != 'high':
        raise HTTPException(409, 'This investigation does not justify containment')
    proposal = {'investigation_id': report_id, 'asset_id': report['asset_id'],
                'requested_by': user['id'], 'status': 'pending', 'simulation': True}
    record_id = store.save(user['tenant'], 'proposal', proposal)
    store.audit(user, 'containment.propose', record_id)
    return dict(id=record_id, **proposal)


def approve(store, user, proposal_id):
    with store.connect() as conn:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute('SELECT body FROM records WHERE id=? AND tenant=? AND kind=?',
                           (proposal_id, user['tenant'], 'proposal')).fetchone()
        if not row:
            raise HTTPException(404, 'Proposal not found')
        body = json.loads(row['body'])
        if body['requested_by'] == user['id']:
            raise HTTPException(403, 'A different administrator must approve the request')
        if body['status'] != 'pending':
            raise HTTPException(409, 'Proposal has already been processed')
        body.update(status='simulated', approved_by=user['id'], approved_at=time.time())
        # Only a local record is changed; there is no endpoint isolation integration.
        conn.execute('UPDATE records SET body=? WHERE id=? AND tenant=?',
                     (json.dumps(body), proposal_id, user['tenant']))
    store.audit(user, 'containment.simulate', proposal_id)
    return dict(id=proposal_id, **body)
