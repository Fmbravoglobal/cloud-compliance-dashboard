"""
Cloud Compliance Dashboard
Real-time multi-cloud compliance scoring across AWS, GCP, and Azure.
Evaluates cloud resources against CIS, NIST 800-53, and PCI-DSS controls.
"""

from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="Cloud Compliance Dashboard",
    description="Real-time multi-cloud compliance scoring across CIS, NIST 800-53, and PCI-DSS.",
    version="1.0.0",
)

FRAMEWORKS = ["CIS", "NIST_800_53", "PCI_DSS", "SOC2"]


class ResourceConfig(BaseModel):
    resource_id: str
    resource_type: str
    cloud_provider: str
    encryption_enabled: bool = False
    public_access_blocked: bool = False
    logging_enabled: bool = False
    versioning_enabled: bool = False
    mfa_required: bool = False
    tls_enforced: bool = False
    backup_enabled: bool = False
    least_privilege_iam: bool = False
    network_segmentation: bool = False
    vulnerability_scanning: bool = False
    region: Optional[str] = "us-east-1"
    tags_applied: bool = False


CONTROL_WEIGHTS = {
    "encryption_enabled":       {"CIS": 20, "NIST_800_53": 20, "PCI_DSS": 25, "SOC2": 20},
    "public_access_blocked":    {"CIS": 20, "NIST_800_53": 15, "PCI_DSS": 20, "SOC2": 15},
    "logging_enabled":          {"CIS": 15, "NIST_800_53": 20, "PCI_DSS": 15, "SOC2": 20},
    "versioning_enabled":       {"CIS":  5, "NIST_800_53":  5, "PCI_DSS":  5, "SOC2":  5},
    "mfa_required":             {"CIS": 15, "NIST_800_53": 15, "PCI_DSS": 15, "SOC2": 15},
    "tls_enforced":             {"CIS": 10, "NIST_800_53": 10, "PCI_DSS": 10, "SOC2": 10},
    "backup_enabled":           {"CIS":  5, "NIST_800_53": 10, "PCI_DSS":  5, "SOC2": 10},
    "least_privilege_iam":      {"CIS": 10, "NIST_800_53": 15, "PCI_DSS": 10, "SOC2": 15},
    "network_segmentation":     {"CIS": 10, "NIST_800_53": 10, "PCI_DSS": 10, "SOC2": 10},
    "vulnerability_scanning":   {"CIS":  0, "NIST_800_53":  5, "PCI_DSS":  5, "SOC2":  5},
}


def score_compliance(config: ResourceConfig) -> dict:
    scores = {fw: 0 for fw in FRAMEWORKS}
    max_scores = {fw: 0 for fw in FRAMEWORKS}
    findings = []

    for control, weights in CONTROL_WEIGHTS.items():
        for fw in FRAMEWORKS:
            max_scores[fw] += weights[fw]
            if getattr(config, control, False):
                scores[fw] += weights[fw]
            else:
                findings.append({
                    "control": control,
                    "framework": fw,
                    "points_lost": weights[fw],
                    "remediation": f"Enable {control.replace('_', ' ')} for this resource",
                })

    percentages = {
        fw: round((scores[fw] / max_scores[fw]) * 100, 1) if max_scores[fw] > 0 else 0
        for fw in FRAMEWORKS
    }

    overall = round(sum(percentages.values()) / len(FRAMEWORKS), 1)

    return {
        "scores": percentages,
        "overall_compliance": overall,
        "status": "COMPLIANT" if overall >= 80 else "NON_COMPLIANT" if overall < 60 else "PARTIAL",
        "findings": findings[:10],
    }


@app.get("/")
def root():
    return {"message": "Cloud Compliance Dashboard is running", "frameworks": FRAMEWORKS}


@app.post("/evaluate")
def evaluate(config: ResourceConfig):
    result = score_compliance(config)
    return {
        "resource_id": config.resource_id,
        "resource_type": config.resource_type,
        "cloud_provider": config.cloud_provider,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        **result,
    }
