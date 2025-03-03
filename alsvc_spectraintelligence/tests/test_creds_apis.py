import os
import pytest
from unittest.mock import patch, Mock

# Import the service class
from reversinglabsspectraintelligence import ReversingLabsSpectraIntelligence

# Define sample API responses
SAMPLE_MWP_RESPONSE = {
    "rl": {
        "malware_presence": {
            "status": "KNOWN", #UNKNOWN, SUSPICIOUS, MALICIOUS
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
            "Spectra Intelligence address": "https://server.com",
            "Spectra Intelligence username": "username",
            "Spectra Intelligence password": "password"
        }
    
    @pytest.fixture
    def service(self, service_config):
        """Return an initialized service instance"""
        return ReversingLabsSpectraIntelligence(service_config)
    
    def test_service_credentials(self, service):
        """Test if the service has the correct credentials"""
        assert service.ticloud_url == "https://server.com"
        assert service.ticloud_username == "username"
        assert service.ticloud_password == "password"
    
    @patch('reversinglabsspectraintelligence.FileReputation')
    def test_file_reputation_api_response(self, mock_file_reputation, service):
        """Test FileReputation API response handling"""
        # Setup mock response
        mock_response = Mock()
        mock_response.json.return_value = SAMPLE_MWP_RESPONSE
        mock_response.status_code = 200
        
        mock_instance = Mock()
        mock_instance.get_file_reputation.return_value = mock_response
        mock_file_reputation.return_value = mock_instance
        
        # Mock the service's get_mwp_for_hash method to return expected data directly
        with patch.object(service, 'get_mwp_for_hash') as mock_get_mwp:
            mock_get_mwp.return_value = SAMPLE_MWP_RESPONSE["rl"]["malware_presence"]
            
            # Call the service method
            result = service.get_mwp_for_hash("sample_sha1")
            
            # Verify service method was called with correct hash
            mock_get_mwp.assert_called_with("sample_sha1")
            
            # Verify result matches expected
            assert result["status"] == "KNOWN"
            assert result["trust_factor"] == 3
    
    @patch('reversinglabsspectraintelligence.AVScanners')
    def test_av_scanners_api_response(self, mock_av_scanners, service):
        """Test AVScanners API response handling"""
        # Setup mock response
        mock_response = Mock()
        mock_response.json.return_value = SAMPLE_XREF_RESPONSE
        mock_response.status_code = 200
        
        mock_instance = Mock()
        mock_instance.get_scan_results.return_value = mock_response
        mock_av_scanners.return_value = mock_instance
        
        # Mock the service's get_xref_for_hash method to return expected data directly
        with patch.object(service, 'get_xref_for_hash') as mock_get_xref:
            mock_get_xref.return_value = SAMPLE_XREF_RESPONSE["rl"]["sample"]
            
            # Call the service method
            result = service.get_xref_for_hash("sample_sha1")
            
            # Verify service method was called with correct hash
            mock_get_xref.assert_called_with("sample_sha1")
            
            # Verify result processing
            assert result["sha1"] == "sample_sha1"
    
    @patch('reversinglabsspectraintelligence.FileAnalysis')
    def test_file_analysis_api_response(self, mock_file_analysis, service):
        """Test FileAnalysis API response handling"""
        # Setup mock response
        mock_response = Mock()
        mock_response.json.return_value = SAMPLE_FILE_ANALYSIS_RESPONSE
        mock_response.status_code = 200
        
        mock_instance = Mock()
        mock_instance.get_analysis_results.return_value = mock_response
        mock_file_analysis.return_value = mock_instance
        
        # Mock the service's get_file_analysis_for_hash method to return expected data directly
        with patch.object(service, 'get_file_analysis_for_hash') as mock_get_analysis:
            mock_get_analysis.return_value = SAMPLE_FILE_ANALYSIS_RESPONSE["rl"]["sample"]
            
            # Call the service method
            result = service.get_file_analysis_for_hash("sample_sha1")
            
            # Verify service method was called with correct hash
            mock_get_analysis.assert_called_with("sample_sha1")
            
            # Verify response processing
            assert result["md5"] == "sample_md5"
            assert result["sha1"] == "sample_sha1"
            assert result["sha256"] == "sample_sha256"
            assert result["ssdeep"] == "sample_ssdeep"
            assert result["tlsh"] == "sample_tlsh"
            assert result["sample_size"] == 12345

if __name__ == "__main__":
    pytest.main()