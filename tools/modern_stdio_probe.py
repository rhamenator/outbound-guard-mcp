#!/usr/bin/env python3
"""Network-free modern/legacy stdio conformance slice for the built server."""
import copy
import json
import os
import subprocess
import sys

VERSION = 'io.modelcontextprotocol/protocolVersion'
CAPS = 'io.modelcontextprotocol/clientCapabilities'
INFO = 'io.modelcontextprotocol/clientInfo'
META = {VERSION: '2026-07-28', CAPS: {}}
URI = 'outbound-guard://logs/audit.json'


def main(binary):
    messages, expected = [], []
    def add(method, params=None, code=None, meta=META):
        id_ = len(expected) + 1
        args = copy.deepcopy(params or {})
        if meta is not None:
            args['_meta'] = copy.deepcopy(meta)
        messages.append({'jsonrpc':'2.0', 'id':id_, 'method':method, 'params':args})
        expected.append((id_, code))
        return id_
    # No discovery/initialize prerequisite: capabilities must be self-contained.
    first = add('tools/list')
    discover = add('server/discover')
    for id_ in (1001.0, 10**80, 9007199254740993, 'string-id'):
        add('tools/list')
        messages[-1]['id'] = id_
        expected[-1] = (id_, None)
    repeated = add('tools/list', meta={**META, CAPS:{'com.example/unknown':{}}, 'com.example/private':['SYNTHETIC_META_MARKER']})
    for method in ('resources/list','resources/templates/list','prompts/list'):
        add(method)
    add('resources/read', {'uri':'SYNTHETIC_META_MARKER'}, -32602)
    add('unknown/method', code=-32601)
    future = add('server/discover', meta={VERSION:'2099-01-01', CAPS:{}}, code=-32022)
    for meta in ({CAPS:{}}, {VERSION:'2026-07-28'}, {**META, VERSION:None}, {**META, CAPS:[]},
                 {**META, CAPS:None}, {**META, INFO:{}}, {**META, INFO:[]},
                 {**META, INFO:{'name':1,'version':'1'}}, {**META, CAPS:{'roots':False}},
                 {**META, CAPS:{'sampling':{'tools':False}}}, {**META, CAPS:{'extensions':{'com.example/x':False}}},
                 {**META, 'io.modelcontextprotocol/logLevel':'invalid'},
                 {**META, 'bad key':1}, {**META, '-bad/name':1},
                 {**META, INFO:{'name':'x','version':'1','icons':[{}]}},
                 {**META, INFO:{'name':'x','version':'1','websiteUrl':1}}):
        add('tools/call', {'name':'guarded_fetch','arguments':{'url':'http://127.0.0.1/'}}, -32602, meta)
    add('tools/list', code=-32602, meta=None)
    for cursor in ('unknown', None, 4):
        add('tools/list', {'cursor':cursor}, -32602)
    add('initialize', code=-32601)
    for invalid_id in (None, True, {}, [], 1.5):
        messages.append({'jsonrpc':'2.0','id':invalid_id,'method':'tools/list','params':{'_meta':META}})
        expected.append((None, -32600))
    # Valid notifications never execute tools or produce a response.
    messages.append({'jsonrpc':'2.0','method':'tools/call','params':{'_meta':META,
        'name':'guarded_fetch','arguments':{'url':'http://127.0.0.1/'}}})
    add('tools/call', {'name':'guarded_fetch','arguments':{'url':'http://127.0.0.1/'},'requestState':1}, -32602)
    add('tools/call', {'name':'guarded_fetch','arguments':{'url':'http://127.0.0.1/'},'inputResponses':[]}, -32602)
    empty_audit = add('resources/read', {'uri':URI})
    blocked = add('tools/call', {'name':'guarded_fetch','arguments':{'url':'http://127.0.0.1/'}})
    audited = add('resources/read', {'uri':URI})
    # Explicit legacy initialization still works on the same process.
    legacy = add('initialize', {'protocolVersion':'2025-06-18','capabilities':{},
        'clientInfo':{'name':'legacy-control','version':'1'}}, meta=None)
    messages.append({'jsonrpc':'2.0','method':'notifications/initialized'})
    legacy_list = add('tools/list', meta=None)
    add('tools/list')  # A modern request must not depend on the legacy session.
    payload = b''.join(json.dumps(message).encode() + b'\n' for message in messages)
    env = {key:value for key,value in os.environ.items() if not key.startswith('OUTBOUND_GUARD_')}
    result = subprocess.run([binary], input=payload, capture_output=True, env=env, timeout=15, check=True)
    assert not result.stderr and b'SYNTHETIC_META_MARKER' not in result.stdout
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(replies) == len(expected), (len(replies), len(expected))
    by_id = {}
    for reply, (id_, code) in zip(replies, expected):
        assert reply['jsonrpc'] == '2.0'
        if id_ is None:
            assert 'id' not in reply
        else:
            assert reply['id'] == id_, reply
            by_id[id_] = reply
        if code is not None:
            assert reply['error']['code'] == code and 'result' not in reply, reply
        else:
            assert 'error' not in reply
            if id_ not in (legacy, legacy_list):
                assert reply['result']['resultType'] == 'complete'
                assert reply['result']['_meta']['io.modelcontextprotocol/serverInfo']['name'] == 'outbound-guard-mcp'
    assert by_id[first]['result'] == by_id[repeated]['result'], 'tool list varied with unrelated capabilities'
    assert by_id[discover]['result']['supportedVersions'] == ['2026-07-28']
    assert by_id[first]['result']['cacheScope'] == 'private' and by_id[first]['result']['ttlMs'] == 0
    assert by_id[future]['error']['data'] == {'supported':['2026-07-28'],'requested':'2099-01-01'}
    assert json.loads(by_id[empty_audit]['result']['contents'][0]['text'])['events'] == []
    assert by_id[blocked]['result']['isError'] is True
    assert by_id[blocked]['result']['structuredContent']['rule'] == 'EGRESS_INVALID_HOST'
    events = json.loads(by_id[audited]['result']['contents'][0]['text'])['events']
    assert len(events) == 1 and events[0]['rule'] == 'EGRESS_INVALID_HOST'
    assert by_id[legacy]['result']['protocolVersion'] == '2025-06-18'
    assert 'resultType' not in by_id[legacy_list]['result']
    # Once opened modern, malformed/oversized frames omit an unreadable ID.
    opener = {'jsonrpc':'2.0','id':1,'method':'server/discover','params':{'_meta':META}}
    data = json.dumps(opener).encode()+b'\n{\n'+b'x'*(65536+1)+b'\n'
    bad = subprocess.run([binary], input=data, capture_output=True, env=env, timeout=15, check=True)
    errors = [json.loads(line) for line in bad.stdout.splitlines()][1:]
    assert not bad.stderr and [v['error']['code'] for v in errors] == [-32700,-32600]
    assert all('id' not in value for value in errors)
    subscription = {'jsonrpc':'2.0','id':'sub','method':'subscriptions/listen','params':{'_meta':META,
        'notifications':{'toolsListChanged':True,'resourceSubscriptions':['SYNTHETIC_META_MARKER']}}}
    sub = subprocess.run([binary], input=json.dumps(subscription).encode()+b'\n', capture_output=True, env=env, timeout=5, check=True)
    ack, ended = map(json.loads, sub.stdout.splitlines())
    assert not sub.stderr and b'SYNTHETIC_META_MARKER' not in sub.stdout
    assert ack['method'] == 'notifications/subscriptions/acknowledged'
    assert ack['params']['notifications'] == {} and ack['params']['_meta']['io.modelcontextprotocol/subscriptionId'] == 'sub'
    assert ended['id'] == 'sub' and ended['result']['resultType'] == 'complete'
    assert ended['result']['_meta']['io.modelcontextprotocol/subscriptionId'] == 'sub'
    print(f'modern stdio probe: {len(replies)} correlated/error responses; metadata/version/ID validation, stateless discovery/tools/resources, no malformed dispatch, legacy coexistence and parse/size errors passed')


if __name__ == '__main__':
    main(sys.argv[1])
