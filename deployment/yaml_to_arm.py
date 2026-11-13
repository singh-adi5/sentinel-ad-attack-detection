#!/usr/bin/env python3
"""Convert detections/*/rule.yaml into one ARM template of Sentinel scheduled rules.

Usage:
    python deployment/yaml_to_arm.py > sentinel-rules.arm.json
    az deployment group create -g <RESOURCE_GROUP> \
        --template-file sentinel-rules.arm.json --parameters workspace=<WORKSPACE_NAME>

The template takes the workspace name as its only parameter and holds no
subscription, tenant or workspace identifiers.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

API_VERSION = "2023-02-01"
OPERATORS = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal", "ne": "NotEqual"}
TIMESPAN = re.compile(r"^(\d+)([mhd])$")


def iso8601(value: str) -> str:
    """30m -> PT30M, 1h -> PT1H, 1d -> P1D."""
    match = TIMESPAN.match(str(value))
    if not match:
        raise ValueError(f"unsupported timespan '{value}'")
    amount, unit = match.groups()
    return f"P{amount}D" if unit == "d" else f"PT{amount}{unit.upper()}"


def to_resource(rule: dict) -> dict:
    properties = {
        "displayName": rule["name"],
        "description": " ".join(str(rule["description"]).split()),
        "severity": rule["severity"],
        # Rules are created disabled. Enable each one after tuning its allow-lists.
        "enabled": False,
        "query": rule["query"],
        "queryFrequency": iso8601(rule["queryFrequency"]),
        "queryPeriod": iso8601(rule["queryPeriod"]),
        "triggerOperator": OPERATORS[rule["triggerOperator"]],
        "triggerThreshold": rule["triggerThreshold"],
        "suppressionDuration": "PT5H",
        "suppressionEnabled": False,
        "tactics": rule["tactics"],
        # This API version takes parent technique ids. The sub-technique stays in the description.
        "techniques": sorted({t.split(".")[0] for t in rule["relevantTechniques"]}),
        "entityMappings": rule["entityMappings"],
        "incidentConfiguration": {
            "createIncident": True,
            "groupingConfiguration": {
                "enabled": False,
                "reopenClosedIncident": False,
                "lookbackDuration": "PT5H",
                "matchingMethod": "AllEntities",
                "groupByEntities": [],
                "groupByAlertDetails": [],
                "groupByCustomDetails": [],
            },
        },
    }
    for optional in ("customDetails", "eventGroupingSettings"):
        if rule.get(optional):
            properties[optional] = rule[optional]
    return {
        "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
        "apiVersion": API_VERSION,
        "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/{rule['id']}')]",
        "kind": "Scheduled",
        "properties": properties,
    }


def build_template(root: Path) -> dict:
    rule_paths = sorted((root / "detections").glob("*/rule.yaml"))
    if not rule_paths:
        raise SystemExit(f"no rule.yaml files found under {root / 'detections'}")
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspace": {
                "type": "string",
                "metadata": {"description": "Name of the Log Analytics workspace that has Sentinel enabled."},
            }
        },
        "resources": [to_resource(yaml.safe_load(p.read_text(encoding="utf-8"))) for p in rule_paths],
    }


if __name__ == "__main__":
    repo_root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
    json.dump(build_template(repo_root), sys.stdout, indent=2)
    sys.stdout.write("\n")
