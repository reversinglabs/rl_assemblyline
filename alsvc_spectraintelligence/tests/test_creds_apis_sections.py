import os
import pytest
import json
from unittest.mock import patch, Mock

# Import the service class
from reversinglabsspectraintelligence import ReversingLabsSpectraIntelligence
from ReversingLabs.SDK.helper import NotFoundError

# Define some sample data for mocking API responses
SAMPLE_MWP_RESPONSE = {
    "rl": {
        "malware_presence": {
            "status": "KNOWN",
            "trust_factor": 3
        }
    }
}

SAMPLE_XREF_RESPONSE = {
    "rl": {
        "sample": {
            "sha1": "sample_sha1",
            "xref": [{"results": [], "scanners": []}]
        }
    }
}

SAMPLE_FILE_ANALYSIS_RESPONSE = {
    "rl": {
        "sample": {
            "md5": "sample_md5",
            "sha1": "sample_sha1",
            "sha256": "sample_sha256",
            "ssdeep": "sample_ssdeep",
            "tlsh": "sample_tlsh",
            "sample_size": 12345,
            "analysis": {
                "entries": [{
                    "tc_report": {
                        "story": "This is a sample story",
                        "info": {
                            "identification": {"name": "Test File"},
                            "file": {"file_type": "PE", "proposed_filename": "test.exe", "file_subtype": "DLL"}
                        },
                        "indicators": [],
                        "metadata": {
                            "attack": {"tactics": []},
                            "certificate": {"certificates": []}
                        },
                        "interesting_strings": []
                    },
                    "record_time": "2023-01-01"
                }]
            },
            "xref": {
                "sample_type": "PE32",
                "first_seen": "2023-01-01",
                "last_seen": "2023-02-01",
                "entries": [{"info": {"scanners": []}}]
            },
            "sources": {"entries": [{"properties": [{"name": "file_name", "value": "test.exe"}], "record_time": "2023-01-01"}]},
            "relationships": {"container_sample_sha1": [], "parent_sample_sha1": []}
        }
    }
}

class TestReversingLabsSpectraIntelligence:
    
    @pytest.fixture(autouse=True)
    def setup_environment(self):
        """Set up environment variables needed for testing"""
        os.environ["SERVICE_MANIFEST_PATH"] = os.path.join(os.path.dirname(__file__), "..", "service_manifest.yml")
    
    @pytest.fixture
    def service_config(self):
        """Return a standard service config"""
        return {
            "Spectra Intelligence address": "server.com",
            "Spectra Intelligence username": "username",
            "Spectra Intelligence password": "password"
        }
    
    @pytest.fixture
    def service(self, service_config):
        """Return an initialized service instance"""
        return ReversingLabsSpectraIntelligence(service_config)
    
    def test_service_init(self, service):
        """Test if the service can be initialized properly"""
        # Check basic service attributes
        assert service is not None
        assert service.ticloud_url == "https://server.com"
        assert service.ticloud_username == "username"
        assert service.ticloud_password == "password"
        
        # Check required methods
        assert hasattr(service, "start")
        assert hasattr(service, "execute")
        assert hasattr(service, "get_mwp_for_hash")
        assert hasattr(service, "get_xref_for_hash")
        assert hasattr(service, "get_file_analysis_for_hash")
    
    def test_mwp_heuristic_mapping(self, service):
        """Test mapping of MWP statuses to heuristics"""
        # Test KNOWN mapping
        mwp_base = {"status": "KNOWN", "trust_factor": 3}
        assert service.get_mwp_heuristic(mwp_base) == 4
        
        # Test MALICIOUS mapping
        mwp_base = {"status": "MALICIOUS", "threat_level": 3}
        assert service.get_mwp_heuristic(mwp_base) == 14
        
        # Test SUSPICIOUS mapping
        mwp_base = {"status": "SUSPICIOUS", "threat_level": 2}
        assert service.get_mwp_heuristic(mwp_base) == 8
    
    @patch('reversinglabsspectraintelligence.extract_timeline')
    @patch('reversinglabsspectraintelligence.extract_mitre_attacks')
    @patch('reversinglabsspectraintelligence.extract_scanners')
    @patch('reversinglabsspectraintelligence.extract_certificate_names')
    @patch('reversinglabsspectraintelligence.extract_indicators')
    @patch('reversinglabsspectraintelligence.FileReputation')
    @patch('reversinglabsspectraintelligence.AVScanners')
    @patch('reversinglabsspectraintelligence.FileAnalysis')
    def test_execute_with_mocked_apis(self, mock_file_analysis, mock_av_scanners, 
                                      mock_file_reputation, mock_extract_indicators,
                                      mock_extract_certificate_names, mock_extract_scanners,
                                      mock_extract_mitre_attacks, mock_extract_timeline,
                                      service):
        """Test execution flow with mocked API responses"""
        # Mock the extraction functions to return appropriate ResultSection objects
        from assemblyline_v4_service.common.result import ResultSection, ResultTimelineSection

        # Create mock result sections
        mock_timeline_section = ResultTimelineSection("Mock Timeline")
        mock_extract_timeline.return_value = mock_timeline_section
        
        mock_mitre_section = ResultSection("Mock MITRE")
        mock_extract_mitre_attacks.return_value = mock_mitre_section
        
        mock_scanner_section = ResultSection("Mock Scanners")
        mock_extract_scanners.return_value = mock_scanner_section
        
        mock_extract_certificate_names.return_value = ["Cert1", "Cert2"]
        mock_extract_indicators.return_value = [{"indicator": "test"}]
        
        # Create mock API responses
        mock_mwp_response = Mock()
        mock_mwp_response.json.return_value = SAMPLE_MWP_RESPONSE
        
        mock_xref_response = Mock()
        mock_xref_response.json.return_value = SAMPLE_XREF_RESPONSE
        
        mock_file_analysis_response = Mock()
        mock_file_analysis_response.json.return_value = SAMPLE_FILE_ANALYSIS_RESPONSE
        
        # Configure mocks to return our responses
        mock_file_reputation_instance = Mock()
        mock_file_reputation_instance.get_file_reputation.return_value = mock_mwp_response
        mock_file_reputation.return_value = mock_file_reputation_instance
        
        mock_av_scanners_instance = Mock()
        mock_av_scanners_instance.get_scan_results.return_value = mock_xref_response
        mock_av_scanners.return_value = mock_av_scanners_instance
        
        mock_file_analysis_instance = Mock()
        mock_file_analysis_instance.get_analysis_results.return_value = mock_file_analysis_response
        mock_file_analysis.return_value = mock_file_analysis_instance
        
        # Create a mock request object
        mock_request = Mock()
        mock_request.sha1 = "sample_sha1"
        mock_request.file_path = "/tmp/test_file.exe"
        
        # Execute the service
        service.execute(mock_request)
        
        # Verify API calls were made with the correct parameters
        mock_file_analysis_instance.get_analysis_results.assert_called_with(hash_input="sample_sha1")
        mock_file_reputation_instance.get_file_reputation.assert_called_with(hash_input="sample_sha1")
        mock_av_scanners_instance.get_scan_results.assert_called_with(hash_input="sample_sha1")
        
        # Verify result was set on the request
        assert mock_request.result is not None
    
    @patch('reversinglabsspectraintelligence.FileAnalysis')
    def test_execute_with_notfound_error(self, mock_file_analysis, service):
        """Test execution flow when file analysis returns NotFoundError"""
        # Configure mock to raise NotFoundError
        mock_file_analysis_instance = Mock()
        mock_file_analysis_instance.get_analysis_results.side_effect = NotFoundError("Not found")
        mock_file_analysis.return_value = mock_file_analysis_instance
        
        # Create a mock request object
        mock_request = Mock()
        mock_request.sha1 = "nonexistent_sha1"
        mock_request.file_path = "/tmp/missing_file.exe"
        
        # Execute the service
        service.execute(mock_request)
        
        # Verify the API call was made
        mock_file_analysis_instance.get_analysis_results.assert_called_with(hash_input="nonexistent_sha1")
        
        # Verify a result was set on the request
        assert mock_request.result is not None
        
    def test_rearrange_xref_output(self, service):
        """Test the rearrangement of XREF output"""
        # Sample XREF input
        xref_input = {
            "sha1": "sample_sha1",
            "sha256": "sample_sha256",
            "xref": [{
                "scanners": ["scanner1", "scanner2"],
                "results": [
                    {"scanner": "scanner1", "result": "malware"},
                    {"scanner": "scanner2", "result": ""}
                ]
            }]
        }
        
        # Test the rearrangement
        output = service.rearrange_xref_output(xref_input)
        
        # Verify the output structure
        assert "sha1" in output
        assert "sha256" in output
        assert "scanners" in output
        assert "results" in output
        assert len(output["results"]) == 1  # Only results with non-empty "result" field
        assert output["results"][0]["result"] == "malware"

if __name__ == "__main__":
    pytest.main()
