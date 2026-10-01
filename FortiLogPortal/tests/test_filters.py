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
