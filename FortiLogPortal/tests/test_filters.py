from datetime import datetime

import pytest
from pydantic import ValidationError

from app.services.faz_filters import LogQuery

P = {"start": datetime(2026, 10, 1, 8), "end": datetime(2026, 10, 1, 9)}


def test_filter_expression_with_all_fields():
    q = LogQuery(logtype="webfilter", srcip="10.0.0.5", dstip="10.1.0.0/16", srcport=5000, dstport="443",
                 user="joao.silva", url="/login?x=1", hostname="facebook.com", policy="12",
                 profile="WebFilter_Corp", srcintf="lan", dstintf="wan1", only_blocked=True, **P)
    assert q.filter_expr() == (
        'srcip=10.0.0.5 and dstip=10.1.0.0/16 and srcport=5000 and dstport=443 and user~"joao.silva" '
        'and url~"/login?x=1" and hostname~"facebook.com" and policyid=12 and profile~"WebFilter_Corp" '
        'and srcintf~"lan" and dstintf~"wan1" and action=blocked')


def test_policy_name_and_dns_domain_field():
    q = LogQuery(logtype="dns", policy="Internet_Corporativa", hostname="xyz.com", **P)
    assert q.filter_expr() == 'qname~"xyz.com" and policyname~"Internet_Corporativa"'


def test_explicit_action_wins_over_only_blocked():
    assert LogQuery(logtype="traffic", action="accept", only_blocked=True, **P).filter_expr() == "action=accept"
    assert LogQuery(logtype="traffic", only_blocked=True, **P).filter_expr() == "action=deny"


@pytest.mark.parametrize("field,value", [
    ("user", 'x" or srcip=1.1.1.1 or user~"y'),
    ("hostname", "a\\b"),
    ("srcip", "10.0.0.300"),
    ("logtype", "anything"),
    ("adom", "root;drop"),
    ("action", "accept or 1"),
    ("dstport", 70000),
])
def test_rejects_injection_and_invalid_values(field, value):
    with pytest.raises(ValidationError):
        LogQuery(**{field: value}, **P)


def test_period_must_be_ordered_and_limit_capped():
    with pytest.raises(ValidationError):
        LogQuery(start=P["end"], end=P["start"])
    assert LogQuery(limit=999999, **P).limit == 1000


def test_devname_app_and_category_filters():
    from datetime import datetime
    from app.services.faz_filters import LogQuery
    q = LogQuery(start=datetime(2026, 10, 1, 10), end=datetime(2026, 10, 1, 11), devname="fw-br-al-maceio055",
                 app="YouTube", category="Games", logtype="webfilter")
    assert q.filter_expr() == 'devname~"fw-br-al-maceio055" and app~"YouTube" and catdesc~"Games"'


def test_added_filters_include_and_exclude():
    from datetime import datetime
    import pytest
    from app.services.faz_filters import LogQuery
    q = LogQuery(start=datetime(2026, 10, 1, 10), end=datetime(2026, 10, 1, 11), logtype="traffic", filters=[
        {"field": "user", "op": "=", "value": "ALUNOS.MACEIO"},
        {"field": "srcip", "op": "!=", "value": "10.55.10.57"},
        {"field": "dstport", "op": "~", "value": "443"},
        {"field": "policy", "op": "!=", "value": "14"},
        {"field": "hostname", "op": "~", "value": "microsoft"},
    ])
    assert q.filter_expr() == ('user="ALUNOS.MACEIO" and srcip!=10.55.10.57 and dstport=443 and policyid!=14 '
                               'and hostname~"microsoft"')
    for bad in ({"field": "user", "value": 'a" or 1=1'}, {"field": "srcip", "value": "x"}, {"field": "evil", "value": "1"},
                {"field": "user", "op": "or", "value": "a"}):
        with pytest.raises(Exception):
            LogQuery(start=datetime(2026, 10, 1, 10), end=datetime(2026, 10, 1, 11), filters=[bad])


def test_machine_name_and_mac_filters():
    q = LogQuery(logtype="traffic", filters=[{"field": "srcmac", "op": "~", "value": "00-1A-2B-3C-4D-5E"},
                                             {"field": "srcname", "op": "~", "value": "NB-ADM"}], **P)
    assert q.filter_expr() == 'srcmac="00:1a:2b:3c:4d:5e" and srcname~"NB-ADM"'
    with pytest.raises(ValidationError):
        LogQuery(logtype="traffic", filters=[{"field": "srcmac", "value": "00:1a:2b"}], **P)
