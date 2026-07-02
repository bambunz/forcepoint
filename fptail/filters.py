from smc_monitoring.models.constants import LogField, Alerts, Actions
from smc_monitoring.models.filters import InFilter, TranslatedFilter
from smc_monitoring.models.values import (
    ConstantValue,
    FieldValue,
    IPValue,
    ServiceValue,
)

SEVERITY_MAP = {
    "info": Alerts.INFO,
    "low": Alerts.LOW,
    "high": Alerts.HIGH,
    "critical": Alerts.CRITICAL,
}

ACTION_MAP = {
    "allow": Actions.ALLOW,
    "permit": Actions.PERMIT,
    "discard": Actions.DISCARD,
    "block": Actions.BLOCK,
    "refuse": Actions.REFUSE,
    "terminate": Actions.TERMINATE,
}


class FilterError(Exception):
    pass


def _map(value, table, label):
    key = value.lower()
    if key not in table:
        raise FilterError(
            "unknown %s '%s' - choose from: %s" % (label, value, ", ".join(sorted(table)))
        )
    return table[key]


def build_filters(args) -> list:
    """Translate parsed CLI args into a list of InFilter objects (AND'd together)."""
    clauses = []

    if args.severity:
        constants = [_map(v, SEVERITY_MAP, "severity") for v in args.severity]
        clauses.append(InFilter(FieldValue(LogField.ALERTSEVERITY), [ConstantValue(*constants)]))

    if args.action:
        constants = [_map(v, ACTION_MAP, "action") for v in args.action]
        clauses.append(InFilter(FieldValue(LogField.ACTION), [ConstantValue(*constants)]))

    if args.src:
        clauses.append(InFilter(FieldValue(LogField.SRC), [IPValue(*args.src)]))

    if args.dst:
        clauses.append(InFilter(FieldValue(LogField.DST), [IPValue(*args.dst)]))

    if args.sender:
        clauses.append(InFilter(FieldValue(LogField.NODEID), [IPValue(*args.sender)]))

    if args.service:
        clauses.append(InFilter(FieldValue(LogField.SERVICE), [ServiceValue(*args.service)]))

    if args.expr:
        t_filter = TranslatedFilter()
        t_filter.update_filter(args.expr)
        clauses.append(t_filter)

    return clauses


def apply_filters(query, clauses):
    if not clauses:
        return
    if len(clauses) == 1:
        query.update_filter(clauses[0])
    else:
        query.add_and_filter(clauses)
