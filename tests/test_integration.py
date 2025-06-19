"""Integration tests for the full workflow."""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch

from src.ocsf_parser import OCSFParser
from src.filters import FilterEngine
from tests.fixtures.sample_ocsf import get_sample_findings_list


class TestOCSFToPlexTracWorkflow:
    """Test the complete workflow from OCSF parsing to PlexTrac format conversion."""

    def test_parse_and_filter_workflow(self):
        """Test parsing OCSF file and applying filters."""
        # Create temporary OCSF file
        sample_findings = get_sample_findings_list()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ocsf.json", delete=False) as f:
            json.dump(sample_findings, f, indent=2)
            temp_file = Path(f.name)

        try:
            # Parse the file
            parser = OCSFParser()
            findings = parser.parse_file(temp_file)

            # Should parse all 4 findings
            assert len(findings) == 4

            # Apply FAIL filter
            filter_engine = FilterEngine()
            filter_engine.create_from_preset({"filters": {"status": ["FAIL"]}})

            result = filter_engine.apply_filters(findings)

            # Should have 3 FAIL findings
            assert len(result.filtered_findings) == 3

            # Verify the findings have correct data
            fail_findings = result.filtered_findings
            severities = [f.severity for f in fail_findings]
            assert "Critical" in severities
            assert "High" in severities
            assert "Low" in severities

        finally:
            # Clean up temp file
            temp_file.unlink()

    def test_finding_conversion_workflow(self):
        """Test converting OCSF findings to PlexTrac format."""
        # Parse sample findings
        parser = OCSFParser()
        sample_data = get_sample_findings_list()

        findings = []
        for data in sample_data:
            finding = parser._parse_finding(data)
            if finding:
                findings.append(finding)

        # Test the conversion logic used in menu_import.py
        from src.api.endpoints import Finding

        converted_findings = []
        for ocsf_finding in findings:
            # Simulate the conversion process
            title = ocsf_finding.message or "Security Finding"
            description = (
                f"**Finding**: {ocsf_finding.message}\n**Resource**: {ocsf_finding.resource_name}"
            )

            plextrac_finding = Finding(
                title=title,
                description=description,
                severity=ocsf_finding.severity,
                status="Open",
                references=[],
                affected_assets={},
                recommendation="",
            )
            converted_findings.append(plextrac_finding)

        # Should have converted all findings
        assert len(converted_findings) == 4

        # Check that fields are properly mapped
        for i, finding in enumerate(converted_findings):
            assert finding.title is not None
            assert finding.description is not None
            assert finding.severity in ["Critical", "High", "Medium", "Low"]
            assert finding.status == "Open"

    @patch("src.plextrac_client.PlexTracClient")
    def test_mock_import_workflow(self, mock_client_class):
        """Test the import workflow with mocked PlexTrac client."""
        # Setup mock
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.is_authenticated.return_value = True

        # Mock successful import
        from src.plextrac_client import ImportResult

        mock_result = ImportResult(
            success=True,
            total_findings=3,
            imported_findings=3,
            duplicate_findings=0,
            failed_findings=0,
        )
        mock_client.import_findings.return_value = mock_result

        # Test the workflow
        parser = OCSFParser()
        sample_data = get_sample_findings_list()

        findings = []
        for data in sample_data:
            finding = parser._parse_finding(data)
            if finding:
                findings.append(finding)

        # Apply filter
        filter_engine = FilterEngine()
        filter_engine.create_from_preset({"filters": {"status": ["FAIL"]}})
        result = filter_engine.apply_filters(findings)

        # Should have 3 FAIL findings to import
        assert len(result.filtered_findings) == 3

        # Mock import call
        import_result = mock_client.import_findings("client123", "report456", [])

        # Verify mock was called and returned expected result
        assert import_result.success is True
        assert import_result.total_findings == 3
        assert import_result.imported_findings == 3


class TestConfigurationIntegration:
    """Test configuration system integration."""

    def test_severity_mapping_integration(self):
        """Test that severity mapping from config works correctly."""
        from src.utils.config import get_config

        config = get_config()
        severity_map = config.mapping.severity

        # Verify the mapping exists and has expected values
        assert 1 in severity_map  # Critical
        assert 2 in severity_map  # High
        assert 3 in severity_map  # Medium
        assert 4 in severity_map  # Low

        assert severity_map[1] == "Critical"
        assert severity_map[2] == "High"
        assert severity_map[3] == "Medium"
        assert severity_map[4] == "Low"

        # Check if Informational level exists (may or may not be in config)
        if 5 in severity_map:
            assert severity_map[5] == "Informational"

    def test_ocsf_parser_uses_config_mapping(self):
        """Test that OCSF parser uses config for severity mapping."""
        parser = OCSFParser()

        # Test with a sample finding
        sample_data = {
            "message": "Test finding",
            "severity_id": 2,
            "severity": "Should be ignored",  # Parser should use severity_id + config
            "status": "New",
            "status_id": 1,
            "status_code": "FAIL",
        }

        finding = parser._parse_finding(sample_data)

        # Should use config mapping for severity_id=2 -> "High"
        assert finding.severity == "High"
        assert finding.severity_id == 2


class TestErrorHandling:
    """Test error handling in the integration workflow."""

    def test_invalid_ocsf_file_handling(self):
        """Test handling of invalid OCSF files."""
        # Create invalid JSON file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("invalid json content {")
            temp_file = Path(f.name)

        try:
            parser = OCSFParser()

            with pytest.raises(ValueError, match="Invalid JSON format"):
                parser.parse_file(temp_file)

        finally:
            temp_file.unlink()

    def test_malformed_finding_handling(self):
        """Test handling of malformed OCSF findings."""
        parser = OCSFParser()

        # Missing required fields
        malformed_data = {
            "some_field": "value"
            # Missing message, severity_id, etc.
        }

        # Should return None for invalid finding
        finding = parser._parse_finding(malformed_data)
        assert finding is None

    def test_filter_edge_cases(self):
        """Test filter edge cases."""
        filter_engine = FilterEngine()

        # Empty findings list
        result = filter_engine.apply_filters([])
        assert result.original_count == 0
        assert result.filtered_count == 0
        assert len(result.filtered_findings) == 0

        # No filters applied
        parser = OCSFParser()
        sample_data = get_sample_findings_list()

        findings = []
        for data in sample_data:
            finding = parser._parse_finding(data)
            if finding:
                findings.append(finding)

        result = filter_engine.apply_filters(findings)

        # Should return all findings unchanged
        assert result.original_count == len(findings)
        assert result.filtered_count == len(findings)
        assert len(result.filtered_findings) == len(findings)
