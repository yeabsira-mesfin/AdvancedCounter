from test_security import login, setup


def high_report(client):
    alerts=client.get('/api/alerts').json()
    alert=next(a for a in alerts if a['severity']=='high')
    res=client.post('/api/investigations',json={'alert_id':alert['id']})
    assert res.status_code==201
    return res.json()


def test_investigation_collects_evidence_but_does_not_execute_log_instructions(setup):
    client=login(setup,'analyst@alpha.test')
    result=high_report(client)
    assert result['severity']=='high'
    assert result['untrusted_instruction_detected']
    assert [t['tool'] for t in result['trace']]==['get_asset','search_logs','lookup_indicator']
    assert len(result['timeline'])==7
    assert client.get('/api/proposals').json()==[]


def test_normal_alert_remains_low_and_cannot_propose_containment(setup):
    client=login(setup)
    alert=next(a for a in client.get('/api/alerts').json() if a['severity']=='low')
    result=client.post('/api/investigations',json={'alert_id':alert['id']}).json()
    assert result['severity']=='low'
    assert client.post('/api/proposals',json={'investigation_id':result['id']}).status_code==409


def test_unauthorized_tools_and_cross_tenant_assets_rejected(setup):
    client=login(setup)
    assert client.post('/api/tools/execute',json={'name':'shell','asset_id':'alpha-laptop-01'}).status_code==403
    assert client.post('/api/tools/execute',json={'name':'get_asset','asset_id':'beta-laptop-01'}).status_code==404
    assert client.post('/api/tools/execute',json={'name':'get_asset','asset_id':'../../etc/passwd'}).status_code==403


def test_two_person_approval_and_replay_protection(setup):
    admin=login(setup)
    report=high_report(admin)
    proposal=admin.post('/api/proposals',json={'investigation_id':report['id']}).json()
    route='/api/proposals/'+proposal['id']+'/approve'
    assert admin.post(route).status_code==403
    analyst=login(setup,'analyst@alpha.test')
    assert analyst.post(route).status_code==403
    beta=login(setup,'admin@beta.test')
    assert beta.post(route).status_code==404
    reviewer=login(setup,'reviewer@alpha.test')
    accepted=reviewer.post(route)
    assert accepted.status_code==200 and accepted.json()['simulation'] is True
    assert accepted.json()['status']=='simulated'
    assert reviewer.post(route).status_code==409


def test_viewer_is_read_only(setup):
    viewer=login(setup,'viewer@alpha.test')
    assert viewer.post('/api/investigations',json={'alert_id':'anything'}).status_code==403
    assert viewer.post('/api/tools/execute',json={'name':'get_asset','asset_id':'alpha-laptop-01'}).status_code==403


def test_cross_tenant_alert_cannot_be_investigated(setup):
    beta=login(setup,'admin@beta.test')
    alert=beta.get('/api/alerts').json()[0]
    assert login(setup).post('/api/investigations',json={'alert_id':alert['id']}).status_code==404
