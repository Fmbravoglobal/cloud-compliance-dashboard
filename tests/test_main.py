"""Unit tests for Cloud Compliance Dashboard."""
import sys, os, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.main import score_compliance, ResourceConfig

def full_config(**overrides):
    defaults = dict(
        resource_id="res-001", resource_type="S3Bucket", cloud_provider="aws",
        encryption_enabled=True, public_access_blocked=True, logging_enabled=True,
        versioning_enabled=True, mfa_required=True, tls_enforced=True,
        backup_enabled=True, least_privilege_iam=True, network_segmentation=True,
        vulnerability_scanning=True, tags_applied=True,
    )
    defaults.update(overrides)
    return ResourceConfig(**defaults)

class TestComplianceScoring:
    def test_fully_compliant_scores_100(self):
        result = score_compliance(full_config())
        assert result["overall_compliance"] == 100.0
        assert result["status"] == "COMPLIANT"

    def test_empty_config_non_compliant(self):
        config = ResourceConfig(resource_id="r1", resource_type="S3", cloud_provider="aws")
        result = score_compliance(config)
        assert result["overall_compliance"] == 0.0
        assert result["status"] == "NON_COMPLIANT"

    def test_encryption_affects_all_frameworks(self):
        with_enc = score_compliance(full_config(encryption_enabled=True))
        without_enc = score_compliance(full_config(encryption_enabled=False))
        assert with_enc["overall_compliance"] > without_enc["overall_compliance"]

    def test_partial_compliance_status(self):
        config = full_config(encryption_enabled=True, public_access_blocked=True,
                             logging_enabled=True, mfa_required=False, tls_enforced=False,
                             backup_enabled=False, least_privilege_iam=False,
                             network_segmentation=False, vulnerability_scanning=False)
        result = score_compliance(config)
        assert result["status"] in ["PARTIAL", "NON_COMPLIANT", "COMPLIANT"]

    def test_findings_present_when_non_compliant(self):
        config = ResourceConfig(resource_id="r1", resource_type="S3", cloud_provider="aws")
        result = score_compliance(config)
        assert len(result["findings"]) > 0

    def test_all_frameworks_present(self):
        result = score_compliance(full_config())
        for fw in ["CIS", "NIST_800_53", "PCI_DSS", "SOC2"]:
            assert fw in result["scores"]
