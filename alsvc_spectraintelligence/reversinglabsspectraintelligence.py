import os
import json
import requests

from ReversingLabs.SDK.helper import *
from ReversingLabs.SDK.ticloud import FileReputation, AVScanners, FileAnalysis
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import (
    Result,
    ResultSection,
    BODY_FORMAT,
    ResultTimelineSection,
)

# Constants and mappings
AL_USER_AGENT = "ReversingLabs Assemblyline Spectra Intelligence v1.1.0"

TRUST_FACTOR_KNOWN_TO_HEURISTIC = {0: 1, 1: 2, 2: 3, 3: 4, 4: 5, 5: 6, 6: 7}
THREAT_LEVEL_MALICIOUS_TO_HEURISTIC = {1: 9, 2: 10, 3: 14, 4: 15, 5: 16}
THREAT_LEVEL_SUSPICIOUS_TO_HEURISTIC = {1: 7, 2: 8, 3: 11, 4: 12, 5: 13}


class ReversingLabsSpectraIntelligence(ServiceBase):
    """
    ReversingLabs Service Interface for AssemblyLine.

    This service queries three APIs:
      1. File Reputation (MWP)
      2. AV Scanners (XREF)
      3. File Analysis (RLData)

    The final result sections are added in the following order:
      - First, extracted sections (Story, Timeline, File Hashes, etc.) from File Analysis.
      - Then, the raw JSON outputs (auto-collapsed) from File Reputation, AV Scanners, and File Analysis.
    """

    def __init__(self, config=None):
        super(ReversingLabsSpectraIntelligence, self).__init__(config=config)
        self.ticloud_url = self.config.get("Spectra Intelligence address")
        self.ticloud_username = self.config.get("Spectra Intelligence username")
        self.ticloud_password = self.config.get("Spectra Intelligence password")

    def start(self):
        self.log.debug("Spectra Intelligence service started")

    def execute(self, request):
        """
        Execution flow:
          (A) Retrieve File Analysis (RLData) data and extract sections.
              The extracted sections (Story, Timeline, etc.) are added in closed-by-default mode.
          (B) Append JSON output sections for File Reputation (MWP), AV Scanners (XREF),
              and File Analysis (raw JSON)
        """
        sha1sum = request.sha1
        result = Result()
        sample_file_name = os.path.basename(request.file_path)
        should_drop = False

        # ---------------------------------------------------------------------
        # (A) Call File Analysis API and extract sections
        # ---------------------------------------------------------------------

        # file_analysis_data = self.get_file_analysis_for_hash(sha1sum=sha1sum).json()
        # sample = file_analysis_data["rl"].get("sample", {})

        try:
            analysis_result = self.get_file_analysis_for_hash(sha1sum=sha1sum)
            file_analysis_data = analysis_result.json()
        except NotFoundError:
            file_analysis_section = ResultSection("File Analysis")
            file_analysis_section.add_line(
                "No reference was found for this file. Please ensure that the file has been previously analyzed or resubmit for analysis."
            )
            file_analysis_section.auto_collapse = True
            result.add_section(file_analysis_section)
            request.result = result
            return

        sample = file_analysis_data["rl"].get("sample", {})

        # analysis_result = self.get_file_analysis_for_hash(sha1sum=sha1sum)
        # if analysis_result is None:
        #     file_analysis_section = ResultSection("File Analysis")
        #     file_analysis_section.add_line(
        #         "No reference was found for this file. Please ensure that the file has been previously analyzed or resubmit for analysis."
        #     )
        #     file_analysis_section.auto_collapse = True
        #     result.add_section(file_analysis_section)
        #     request.result = result
        #     return

        # file_analysis_data = analysis_result.json()
        # sample = file_analysis_data["rl"].get("sample", {})


        # 1. Story Section
        story_text = extract_story(file_analysis_data)
        if story_text is not None:
            story_section = ResultSection("File Analysis Story")
            story_section.add_line(story_text)
            story_section.auto_collapse = True
            result.add_section(story_section)

        # 2. Timeline Section
        timeline_section = extract_timeline(file_analysis_data)
        timeline_section.auto_collapse = True
        result.add_section(timeline_section)

        # 3. File Hashes Section
        file_hashes_section = ResultSection("File Hashes")
        possible_hashes = ("md5", "sha1", "sha256", "ssdeep", "tlsh")
        for hash_type in possible_hashes:
            hash_value = sample.get(hash_type)
            if hash_value:
                file_hashes_section.add_line(f"{hash_type.upper()}: {hash_value}")
        file_hashes_section.auto_collapse = True
        result.add_section(file_hashes_section)

        # 4. Source Information Section
        source_info_section = ResultSection("Source Information")
        source_entries = sample.get("sources", {}).get("entries", [{}])[0]
        file_name = next(
            (prop.get("value") for prop in source_entries.get("properties", [])
             if prop.get("name") == "file_name"),
            "N/A"
        )
        cuckoo_parent = next(
            (prop.get("value") for prop in source_entries.get("properties", [])
             if prop.get("name") == "cuckoo_parent"),
            "N/A"
        )
        source_info_section.add_line(f"File Name: {file_name}")
        source_info_section.add_line(f"Cuckoo Parent: {cuckoo_parent}")
        source_info_section.auto_collapse = True
        result.add_section(source_info_section)

        # 5. Sample Relationships Section
        relationships = sample.get("relationships", {})
        relationship_section = ResultSection("Sample Relationships")
        relationship_section.add_line(
            f"Container Sample SHA1: {', '.join(relationships.get('container_sample_sha1', ['N/A']))}"
        )
        relationship_section.add_line(
            f"Parent Sample SHA1: {', '.join(relationships.get('parent_sample_sha1', ['N/A']))}"
        )
        relationship_section.auto_collapse = True
        result.add_section(relationship_section)

        # 6. File Metadata Section
        file_metadata_section = ResultSection("File Metadata")
        file_metadata_section.add_line(f"File Size: {sample.get('sample_size', 'N/A')} bytes")
        file_metadata_section.add_line(
            f"File Type: {sample.get('xref', {}).get('sample_type', 'Unknown')}"
        )
        file_metadata_section.add_line(
            f"File Subtype: {sample.get('analysis', {}).get('entries', [{}])[0].get('tc_report', {}).get('info', {}).get('file', {}).get('file_subtype', 'N/A')}"
        )
        file_metadata_section.auto_collapse = True
        result.add_section(file_metadata_section)

        # 7. Identification Details Section
        identification_details = extract_identification_details(file_analysis_data)
        identification_section = ResultSection("Identification Details")
        for key, value in identification_details.items():
            identification_section.add_line(f"{key}: {value}")
        identification_section.auto_collapse = True
        result.add_section(identification_section)

        # 8. Generated Tags Section
        file_type = identification_details.get("File Type", "N/A")
        interesting_strings = sample.get("analysis", {}).get("entries", [{}])[0] \
                                .get("tc_report", {}) \
                                .get("interesting_strings", [])
        ip_addresses = []
        for s in interesting_strings:
            if s.get("category") == "ipv4":
                ip_addresses.extend(s.get("values", []))
        domain = ip_addresses[0] if ip_addresses else "N/A"
        source_tags = set()
        source_tags.add(f"file_type_{file_type}")
        source_tags.add(domain)
        sources_entries = sample.get("sources", {}).get("entries", [])
        for entry in sources_entries:
            if entry.get("tag"):
                source_tags.add(entry.get("tag"))
            for prop in entry.get("properties", []):
                if prop.get("name") == "tags" and prop.get("value"):
                    source_tags.add(prop.get("value"))
        generated_tags_section = ResultSection("Generated Tags", auto_collapse=True)
        for tag_value in source_tags:
            generated_tags_section.add_tag("source", tag_value)
            generated_tags_section.add_line(f"Source Tag: {tag_value}")
        result.add_section(generated_tags_section)

        # 9. Associated Domains Section
        domains_section = ResultSection("Associated Domains")
        interesting_strings = sample.get("analysis", {}).get("entries", [{}])[0] \
                                .get("tc_report", {}) \
                                .get("interesting_strings", [])
        if interesting_strings:
            for string in interesting_strings:
                if string.get("category") == "ipv4":
                    domains_section.add_line(
                        f"IP Address: {', '.join(string.get('values', []))}"
                    )
        domains_section.auto_collapse = True
        result.add_section(domains_section)

        # 10. MITRE ATT&CK Section
        mitre_attack_section = extract_mitre_attacks(file_analysis_data)
        if mitre_attack_section is not None:
            mitre_attack_section.auto_collapse = True
            result.add_section(mitre_attack_section)

        # 11. Certificate Issuers Section
        certificate_names = extract_certificate_names(file_analysis_data)
        if certificate_names is not None:
            certificate_names_section = ResultSection("Certificate Issuers")
            certificate_names_section.auto_collapse = True
            for cert_tag in certificate_names:
                certificate_names_section.add_line(cert_tag)
            result.add_section(certificate_names_section)

        # 12. Indicators Section
        indicators_data = extract_indicators(file_analysis_data)
        if indicators_data:
            indicators_section = ResultSection(
                "Indicators of Compromise (IoCs)",
                body_format=BODY_FORMAT.TABLE,
                body=json.dumps(indicators_data),
                auto_collapse=True
            )
            result.add_section(indicators_section)

        # 13. Scanners Section
        scanner_section = extract_scanners(file_analysis_data)
        scanner_section.auto_collapse = True
        result.add_section(scanner_section)

        # ---------------------------------
        # (B) Append JSON Output Sections
        # ---------------------------------
        try:
            # File Reputation (MWP) JSON section
            mwp_result = self.get_mwp_for_hash(sha1sum=sha1sum)
            mwp_section = self.return_mwp_section(sample_file_name=sample_file_name,
                                                   mwp_result=mwp_result)
            mwp_section.auto_collapse = True
            result.add_section(mwp_section)
            should_drop = self.will_drop(mwp_result.json())
        except Exception as e:
            result.add_section(ResultSection(
                title_text="File Reputation",
                body=f"An error has occurred: {type(e).__name__} : {str(e)}",
                auto_collapse=True
            ))

        try:
            # AV Scanners (XREF) JSON section
            xref_result = self.get_xref_for_hash(sha1sum=sha1sum)
            xref_section = self.return_xref_section(request=request,
                                                    sha1sum=sha1sum,
                                                    sample_file_name=sample_file_name,
                                                    xref_result=xref_result)
            xref_section.auto_collapse = True
            result.add_section(xref_section)
        except Exception as e:
            self.handle_xref_error(e, sha1sum, sample_file_name, result)

        try:
            # File Analysis (RLData) JSON section
            file_analysis_json_result = self.get_file_analysis_for_hash(sha1sum=sha1sum)
            file_analysis_json_section = self.return_file_analysis_section(file_analysis_json_result)
            file_analysis_json_section.auto_collapse = True
            result.add_section(file_analysis_json_section)
        except Exception as e:
            result.add_section(ResultSection(
                title_text="File Analysis (JSON)",
                body=f"An error has occurred: {type(e).__name__} : {str(e)}",
                auto_collapse=True
            ))

        request.result = result
        if should_drop:
            request.drop()

    # ---------------------------------------------------------------
    # API Query Methods
    # ---------------------------------------------------------------
    def get_mwp_for_hash(self, sha1sum):
        """Queries the MWP API for file reputation."""
        mwp = FileReputation(
            host=self.ticloud_url,
            username=self.ticloud_username,
            password=self.ticloud_password,
            user_agent=AL_USER_AGENT
        )
        return mwp.get_file_reputation(hash_input=str(sha1sum))

    def get_xref_for_hash(self, sha1sum):
        """Queries the XREF API for multi-AV scan results."""
        xref = AVScanners(
            host=self.ticloud_url,
            username=self.ticloud_username,
            password=self.ticloud_password,
            user_agent=AL_USER_AGENT
        )
        return xref.get_scan_results(hash_input=str(sha1sum))

    def get_file_analysis_for_hash(self, sha1sum):
        """Queries the File Analysis API for deep analysis data."""
        file_analysis = FileAnalysis(
            host=self.ticloud_url,
            username=self.ticloud_username,
            password=self.ticloud_password,
            user_agent=AL_USER_AGENT
        )
        return file_analysis.get_analysis_results(hash_input=sha1sum)

    # ---------------------------------------------------------------
    # Return Section Methods
    # ---------------------------------------------------------------
    def return_mwp_section(self, sample_file_name, mwp_result):
        """
        Builds a result section based on the MWP API response.
        """
        mwp_result_json = mwp_result.json()
        if "rl" in mwp_result_json and "malware_presence" in mwp_result_json.get("rl"):
            mwp_base = mwp_result_json["rl"]["malware_presence"]
            if mwp_base.get("status") == "UNKNOWN":
                section = ResultSection(
                    title_text="File Reputation",
                    body=(
                        f"File {sample_file_name} has no reference on ReversingLabs Spectra Intelligence File Reputation. "
                        "It is not being uploaded for further analysis."
                    )
                )
                section.set_heuristic(self.get_mwp_heuristic(mwp_base))
            else:
                section = ResultSection(
                    title_text="File Reputation",
                    body=json.dumps(mwp_base),
                    body_format="JSON"
                )
                section.set_heuristic(self.get_mwp_heuristic(mwp_base))
        else:
            section = ResultSection(
                title_text="File Reputation",
                body="No valid File Reputation report body was found."
            )
        return section

    def return_xref_section(self, request, sha1sum, sample_file_name, xref_result):
        """
        Builds a result section based on the XREF API response.
        """
        xref_result_json = xref_result.json()
        if "rl" in xref_result_json and "sample" in xref_result_json.get("rl"):
            xref_base = xref_result_json["rl"]["sample"]
            xref_output = self.rearrange_xref_output(xref_base)
            xref_section = ResultSection(
                title_text="AV Scanners",
                body=json.dumps(xref_output),
                body_format="JSON"
            )
        else:
            xref_section = ResultSection(
                title_text="AV Scanners",
                body="No valid AV Scanners report body was found."
            )
        return xref_section

    def return_file_analysis_section(self, file_analysis_result):
        """
        Builds a result section based on the File Analysis API response.
        This returns the raw JSON output.
        """
        file_analysis_result_json = file_analysis_result.json()
        if "rl" in file_analysis_result_json and "sample" in file_analysis_result_json.get("rl"):
            section = ResultSection(
                title_text="File Analysis",
                body=json.dumps(file_analysis_result_json, indent=4),
                body_format="JSON"
            )
        else:
            section = ResultSection(
                title_text="File Analysis",
                body="No valid File Analysis report body was found."
            )
        return section

    # ---------------------------------------------------------------
    # Error Handling & Utility Methods
    # ---------------------------------------------------------------
    def handle_xref_error(self, e, sha1sum, sample_file_name, result):
        """
        Handles errors when querying XREF.
        """
        section = ResultSection(
            title_text="AV Scanners",
            body=f"No data present in AV Scanners for file {sample_file_name}: {type(e).__name__} : {str(e)}.",
            auto_collapse=True
        )
        result.add_section(section)

    @staticmethod
    def get_mwp_heuristic(mwp_base):
        """
        Maps malware presence levels to heuristic scores.
        """
        if mwp_base.get("status"):
            status = mwp_base.get("status").lower()
            if status == "malicious":
                if "threat_level" in mwp_base:
                    threat_level = mwp_base.get("threat_level")
                    return THREAT_LEVEL_MALICIOUS_TO_HEURISTIC.get(threat_level)
                return None
            elif status == "suspicious":
                if "threat_level" in mwp_base:
                    threat_level = mwp_base.get("threat_level")
                    return THREAT_LEVEL_SUSPICIOUS_TO_HEURISTIC.get(threat_level)
                return None
            elif status == "known":
                if "trust_factor" in mwp_base:
                    trust_factor = mwp_base.get("trust_factor")
                    return TRUST_FACTOR_KNOWN_TO_HEURISTIC.get(trust_factor)
                return None
            else:
                return 0
        return None

    @staticmethod
    def rearrange_xref_output(xref_result):
        """
        Rearranges XREF scan results into a structured format.
        """
        xref_output = {}
        for key, value in xref_result.items():
            if key != "xref":
                xref_output[key] = value
        detections = [
            result for result in xref_result["xref"][0]["results"]
            if result.get("result") != ""
        ]
        xref_output.update({
            "scanners": xref_result["xref"][0]["scanners"],
            "results": detections
        })
        return xref_output

    @staticmethod
    def will_drop(mwp_json):
        """
        Determines if the file should be dropped based on its status.
        """
        return mwp_json.get("status", "").lower() in ("malicious", "known")


# ---------------------------------------------------------------
# Helper Extraction Functions
# ---------------------------------------------------------------

def get_base_data(json_data):
    tc_report = (
        json_data.get("rl", {})
                 .get("sample", {})
                 .get("analysis", {})
                 .get("entries", [{}])[0]
                 .get("tc_report", {})
    )
    xref_entry = (
        json_data.get("rl", {})
                 .get("sample", {})
                 .get("xref", {})
                 .get("entries", [{}])[0]
    )
    return tc_report, xref_entry


def extract_indicators(json_data):
    tc_report, _ = get_base_data(json_data)
    indicators = tc_report.get("indicators", [])
    table_body = []
    for indicator in indicators:
        indicator_id = indicator.get("id", "N/A")
        category = indicator.get("category", "N/A")
        description = indicator.get("description", "N/A")
        priority = indicator.get("priority", 0)
        if priority >= 4:
            priority_display = f"High ({priority})"
        elif priority == 3:
            priority_display = f"Medium ({priority})"
        else:
            priority_display = f"Low ({priority})"
        table_body.append({
            "Indicator ID": indicator_id,
            "Category": category,
            "Description": description,
            "Priority": priority_display,
        })
    return table_body if table_body else None


def extract_story(json_data):
    tc_report, _ = get_base_data(json_data)
    return tc_report.get("story", None)


def extract_identification_details(json_data):
    tc_report, _ = get_base_data(json_data)
    identification = tc_report.get("info", {}).get("identification", {})
    file_info = tc_report.get("info", {}).get("file", {})
    details = {
        "Identification": identification.get("name", None),
        "Proposed Filename": file_info.get("proposed_filename", None),
        "File Type": file_info.get("file_type", None)
    }
    # Return None if no identification details were found
    return details if any(details.values()) else None


def extract_mitre_attacks(json_data):
    tc_report, _ = get_base_data(json_data)
    metadata = tc_report.get("metadata", {})
    attack_data = metadata.get("attack", {})
    tactics = attack_data.get("tactics", [])
    if not tactics:
        return None
    table_body = []
    for tactic in tactics:
        tactic_id = tactic.get("id", "N/A")
        tactic_name = tactic.get("name", "Unknown Tactic")
        for technique in tactic.get("techniques", []):
            technique_id = technique.get("id", "N/A")
            technique_name = technique.get("name", "Unknown Technique")
            table_body.append({
                "Tactic ID": tactic_id,
                "Tactic Name": tactic_name,
                "Technique ID": technique_id,
                "Technique Name": technique_name
            })
    return ResultSection(
        "MITRE ATT&CK Tactics & Techniques",
        body_format=BODY_FORMAT.TABLE,
        body=json.dumps(table_body),
        auto_collapse=True
    )


def extract_certificate_names(json_data):
    tc_report, _ = get_base_data(json_data)
    metadata = tc_report.get("metadata", {})
    certificates = metadata.get("certificate", {}).get("certificates", [])
    certificate_tags = []
    for cert in certificates:
        subject = cert.get("subject", "")
        common_name = None
        organizational_unit = None
        for part in subject.split(","):
            part = part.strip()
            if part.startswith("commonName="):
                common_name = part.split("=", 1)[1].strip()
            elif part.startswith("organizationalUnitName="):
                organizational_unit = part.split("=", 1)[1].strip()
        if common_name and organizational_unit:
            certificate_tags.append(f"{common_name} ({organizational_unit})")
        elif common_name:
            certificate_tags.append(f"{common_name}")
        elif organizational_unit:
            certificate_tags.append(f"{organizational_unit}")
    return certificate_tags if certificate_tags else None


def extract_scanners(json_data):
    _, xref_entry = get_base_data(json_data)
    scanners_list = xref_entry.get("scanners", [])
    if not scanners_list:
        return None
    table_body = []
    detected_count = 0
    for scanner in scanners_list:
        name = scanner.get("name", "Unknown Scanner")
        result_str = scanner.get("result", "")
        if result_str:
            detected_count += 1
        table_body.append({
            "Scanner": name,
            "Detection Result": result_str if result_str else "No Detection"
        })
    total_scanners = len(scanners_list)
    detection_percentage = (detected_count / total_scanners * 100) if total_scanners > 0 else 0
    section_title = (
        f"Scanner Results ({detected_count} detections out of {total_scanners} scanners "
        f"({detection_percentage:.2f}%) )"
    )
    return ResultSection(
        section_title,
        body_format=BODY_FORMAT.TABLE,
        body=json.dumps(table_body),
        auto_collapse=True
    )

def extract_timeline(json_data):
    timeline_section = ResultTimelineSection("File Analysis Timeline")
    try:
        sample_info = json_data.get("rl", {}).get("sample", {})
        first_seen = sample_info.get("xref", {}).get("first_seen")
        if first_seen:
            timeline_section.add_node(
                title="First Seen",
                content="Sample first observed in external feed.",
                opposite_content=first_seen
            )
        last_seen = sample_info.get("xref", {}).get("last_seen")
        if last_seen:
            timeline_section.add_node(
                title="Last Seen",
                content="Sample last recorded in a scan.",
                opposite_content=last_seen
            )
        sources = sample_info.get("sources", {}).get("entries", [])
        for source in sources:
            record_time = source.get("record_time")
            if record_time:
                timeline_section.add_node(
                    title="Recorded in External Feed",
                    content="Sample reported by an external source.",
                    opposite_content=record_time
                )
        analysis_entry = sample_info.get("analysis", {}).get("entries", [{}])[0]
        analysis_time = analysis_entry.get("record_time")
        if analysis_time:
            timeline_section.add_node(
                title="Analysis Performed",
                content="Sample analyzed by ReversingLabs Spectra Intelligence.",
                opposite_content=analysis_time
            )
        av_scanners = (
            sample_info.get("xref", {})
                       .get("entries", [{}])[0]
                       .get("info", {})
                       .get("scanners", [])
        )
        for scanner in av_scanners:
            scan_time = scanner.get("timestamp")
            scanner_name = scanner.get("name")
            if scan_time:
                timeline_section.add_node(
                    title=f"Scanned by {scanner_name}",
                    content=f"{scanner_name} scanner updated its detection.",
                    opposite_content=scan_time
                )
    except Exception as e:
        timeline_section.add_node(
            title="Error",
            content=f"Error extracting timeline data: {str(e)}",
            opposite_content="N/A"
        )
    return timeline_section