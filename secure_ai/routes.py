import httpx
from fastapi import Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .auth import identity, require_role
from .incident import approve, call_tool, investigate, propose


class InvestigationRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    alert_id: str = Field(min_length=1, max_length=64)


class ProposalRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    investigation_id: str = Field(min_length=1, max_length=64)


class ToolRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=1, max_length=64)
    asset_id: str = Field(min_length=1, max_length=64)


def register(app):
    store = app.state.store

    @app.get('/api/alerts')
    def alerts(user=Depends(identity)):
        return store.records(user['tenant'], 'alert')

    @app.get('/api/investigations')
    def reports(user=Depends(identity)):
        return store.records(user['tenant'], 'investigation')

    @app.post('/api/investigations', status_code=201)
    def run(body: InvestigationRequest, user=Depends(identity)):
        require_role(user, 'admin','analyst')
        if not store.consume('investigate:' + user['id'], 20, 60):
            raise HTTPException(429, 'Investigation limit reached')
        try:
            return investigate(store, user, body.alert_id, app.state.model)
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise HTTPException(503, 'Investigation provider unavailable') from exc

    @app.post('/api/tools/execute')
    def tool(body: ToolRequest, user=Depends(identity)):
        require_role(user, 'admin','analyst')
        if not store.consume('tool:' + user['id'], 60, 60):
            raise HTTPException(429, 'Tool limit reached')
        return call_tool(store, user, body.model_dump())

    @app.get('/api/proposals')
    def proposals(user=Depends(identity)):
        return store.records(user['tenant'], 'proposal')

    @app.post('/api/proposals', status_code=201)
    def proposal(body: ProposalRequest, user=Depends(identity)):
        require_role(user, 'admin','analyst')
        return propose(store, user, body.investigation_id)

    @app.post('/api/proposals/{proposal_id}/approve')
    def approval(proposal_id: str, user=Depends(identity)):
        require_role(user, 'admin')
        return approve(store, user, proposal_id)
