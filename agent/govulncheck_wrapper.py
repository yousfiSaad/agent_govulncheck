"""Wrapper for executing govulncheck and parsing output."""

import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class GovulncheckWrapper:
    """Wrapper for govulncheck command execution."""
    
    def __init__(self, govulncheck_path: str = "govulncheck"):
        """Initialize wrapper.
        
        Args:
            govulncheck_path: Path to govulncheck binary (default: "govulncheck")
        """
        self.govulncheck_path = govulncheck_path
    
    def scan_module(
        self,
        module_path: str,
        output_format: str = "json"
    ) -> Dict:
        """Scan Go module using govulncheck.

        Args:
            module_path: Path to directory containing go.mod
            output_format: Output format ("json" or "text")

        Returns:
            Dictionary with scan results
        """
        module_path = Path(module_path).resolve()
        logger.info(f"🔍 Starting govulncheck scan for module: {module_path}")

        if not (module_path / "go.mod").exists():
            logger.error(f"❌ No go.mod found in {module_path}")
            return {
                "vulnerabilities": [],
                "exit_code": 1,
                "error": f"No go.mod found in {module_path}"
            }

        # Check go.sum exists
        go_sum_path = module_path / "go.sum"
        if not go_sum_path.exists():
            logger.warning(f"⚠️  No go.sum found in {module_path} - dependencies may not be downloaded")

        # Build command - use "." to scan the current module, not "./..."
        cmd = [self.govulncheck_path, "-json", "."]
        logger.info(f"🛠️  Executing command: {' '.join(cmd)}")
        logger.info(f"📂 Working directory: {module_path}")

        try:
            logger.info(f"🔄 Running govulncheck subprocess...")

            # Run govulncheck
            result = subprocess.run(
                cmd,
                cwd=module_path,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            logger.info(f"✅ Subprocess completed with exit code: {result.returncode}")
            logger.info(f"📊 STDOUT length: {len(result.stdout)} characters")
            logger.info(f"⚠️  STDERR length: {len(result.stderr)} characters")

            if result.stderr:
                logger.warning(f"⚠️  STDERR output: {result.stderr.strip()}")

            # Log first 500 chars of stdout for debugging
            if result.stdout:
                logger.debug(f"📄 STDOUT preview: {result.stdout[:500]}{'...' if len(result.stdout) > 500 else ''}")

            # Parse JSON output
            if result.returncode == 0:
                # No vulnerabilities found
                logger.info("✅ govulncheck exit code 0 - No vulnerabilities found")

                # Even with exit code 0, there might be JSON output (config, progress, etc.)
                vulnerabilities = self._parse_json_output(result.stdout)
                if vulnerabilities:
                    logger.info(f"ℹ️  Found {len(vulnerabilities)} JSON objects in output even with exit code 0")
                    return {
                        "vulnerabilities": vulnerabilities,
                        "exit_code": result.returncode,
                        "stdout": result.stdout,
                        "stderr": result.stderr
                    }

                return {
                    "vulnerabilities": [],
                    "exit_code": 0,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
            else:
                # Parse JSON lines - govulncheck outputs multiple JSON objects, one per line
                logger.info("🔍 govulncheck found vulnerabilities (exit code != 0)")
                vulnerabilities = self._parse_json_output(result.stdout)

                logger.info(f"📋 Parsed {len(vulnerabilities)} JSON objects from output")

                # Log what types of objects we found
                osv_count = sum(1 for v in vulnerabilities if isinstance(v, dict) and 'osv' in v)
                finding_count = sum(1 for v in vulnerabilities if isinstance(v, dict) and 'finding' in v)
                config_count = sum(1 for v in vulnerabilities if isinstance(v, dict) and 'config' in v)
                sbom_count = sum(1 for v in vulnerabilities if isinstance(v, dict) and 'SBOM' in v)

                logger.info(f"📊 Breakdown: {osv_count} OSVs, {finding_count} findings, {config_count} configs, {sbom_count} SBOMs")

                return {
                    "vulnerabilities": vulnerabilities,
                    "exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }

        except subprocess.TimeoutExpired:
            logger.error("⏰ Scan timeout after 5 minutes")
            return {
                "vulnerabilities": [],
                "exit_code": 1,
                "error": "Scan timeout after 5 minutes"
            }
        except Exception as e:
            logger.error(f"💥 Exception during scan: {e}", exc_info=True)
            return {
                "vulnerabilities": [],
                "exit_code": 1,
                "error": str(e)
            }

    def _parse_json_output(self, stdout: str) -> List[Dict]:
        """Parse JSON output from govulncheck.

        govulncheck outputs multiple JSON objects, one per line:
        - config: Scanner configuration
        - SBOM: Software Bill of Materials
        - osv: Open Source Vulnerability entries
        - finding: Actual vulnerability findings with callstacks

        Args:
            stdout: Raw stdout from govulncheck

        Returns:
            List of parsed JSON objects
        """
        vulnerabilities = []
        lines = stdout.strip().split('\n')
        logger.debug(f"📝 Parsing {len(lines)} lines of JSON output")

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                vulnerabilities.append(data)

                # Log what type of object this is
                if isinstance(data, dict):
                    obj_type = "unknown"
                    if 'config' in data:
                        obj_type = "config"
                    elif 'SBOM' in data:
                        obj_type = "SBOM"
                    elif 'osv' in data:
                        obj_type = "OSV"
                    elif 'finding' in data:
                        obj_type = "finding"

                    logger.debug(f"✅ Line {line_num}: Parsed {obj_type} object")

                    # For findings, log the OSV ID
                    if obj_type == "finding" and 'osv' in data.get('finding', {}):
                        logger.info(f"🚨 Found vulnerability: {data['finding']['osv']}")

                else:
                    logger.debug(f"✅ Line {line_num}: Parsed {type(data).__name__}")

            except json.JSONDecodeError as e:
                logger.warning(f"❌ Line {line_num}: Failed to parse JSON - {e}")
                logger.debug(f"❌ Problematic line: {line[:200]}...")
                continue

        logger.info(f"📊 Successfully parsed {len(vulnerabilities)} JSON objects")
        return vulnerabilities
    
    def scan_file(self, file_path: str) -> Dict:
        """Scan a single Go file (go.mod or go.sum).

        Args:
            file_path: Path to go.mod or go.sum file

        Returns:
            Dictionary with scan results
        """
        file_path = Path(file_path).resolve()
        logger.info(f"📁 Scanning file: {file_path}")

        module_dir = file_path.parent
        logger.info(f"📂 Extracted module directory: {module_dir}")

        if not (module_dir / "go.mod").exists():
            logger.error(f"❌ No go.mod found in {module_dir}")
            return {
                "vulnerabilities": [],
                "exit_code": 1,
                "error": f"No go.mod found in {module_dir}"
            }

        logger.info(f"✅ Found go.mod, proceeding to scan module: {module_dir}")
        return self.scan_module(str(module_dir))
    
    def convert_to_oxo_format(self, govulncheck_result: Dict) -> List[Dict]:
        """Convert govulncheck output to OXO vulnerability format.

        govulncheck outputs separate objects:
        - "osv": Contains vulnerability metadata
        - "finding": Contains callstack information when vuln is used

        This method combines them to create OXO vulnerability reports.

        Args:
            govulncheck_result: Result from scan_module or scan_file

        Returns:
            List of OXO-formatted vulnerability dictionaries
        """
        logger.info("🔄 Starting conversion to OXO format")
        vulnerabilities = govulncheck_result.get("vulnerabilities", [])
        logger.info(f"📊 Processing {len(vulnerabilities)} raw vulnerability objects")

        # Separate OSVs and findings
        osv_map = {}
        finding_map = {}

        # First pass: collect all OSVs
        for item in vulnerabilities:
            if isinstance(item, dict):
                if 'osv' in item:
                    osv_id = item['osv']['id']
                    osv_map[osv_id] = item['osv']
                    logger.debug(f"📋 Found OSV: {osv_id}")
                elif 'finding' in item:
                    osv_id = item['finding']['osv']
                    finding_map[osv_id] = item['finding']
                    logger.debug(f"🚨 Found finding for OSV: {osv_id}")
                else:
                    logger.debug(f"ℹ️  Other object type: {list(item.keys()) if isinstance(item, dict) else type(item)}")

        logger.info(f"📊 Collected {len(osv_map)} OSVs and {len(finding_map)} findings")

        # Second pass: create OXO vulnerabilities
        oxo_vulns = []

        for osv_id, osv_data in osv_map.items():
            logger.debug(f"🔄 Converting OSV {osv_id} to OXO format")

            # Get basic info from OSV
            vuln_id = osv_data.get("id", "UNKNOWN")
            summary = osv_data.get("summary", "")
            details = osv_data.get("details", "")

            # Get affected module info
            affected_module = "unknown"
            affected_version = ""

            # Try to get module info from affected packages
            if "affected" in osv_data:
                for affected in osv_data["affected"]:
                    if "package" in affected:
                        pkg = affected["package"]
                        if isinstance(pkg, dict) and "name" in pkg:
                            affected_module = pkg["name"]
                        elif isinstance(pkg, str):
                            affected_module = pkg
                        break

            # Determine severity from CVSS
            cvss_score = None
            severity = "UNKNOWN"

            if "database_specific" in osv_data:
                db_spec = osv_data["database_specific"]
                if "cvss_score" in db_spec:
                    cvss_score = db_spec["cvss_score"]
                    if cvss_score >= 9.0:
                        severity = "CRITICAL"
                    elif cvss_score >= 7.0:
                        severity = "HIGH"
                    elif cvss_score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"

            # Check if vulnerability is actually used (has finding with callstack)
            is_used = osv_id in finding_map
            logger.info(f"🎯 OSV {osv_id}: is_used={is_used}")

            # Extract references
            references = []
            for ref in osv_data.get("references", []):
                if isinstance(ref, dict):
                    ref_url = ref.get("url", "")
                elif isinstance(ref, str):
                    ref_url = ref
                else:
                    ref_url = str(ref)
                if ref_url:
                    references.append(ref_url)

            # Create OXO vulnerability message
            oxo_vuln = {
                "vulnerability_id": vuln_id,
                "title": summary or f"Vulnerability in {affected_module}",
                "description": details or summary or f"Vulnerability found in {affected_module}",
                "severity": severity,
                "cvss_score": cvss_score,
                "affected_package": affected_module,
                "affected_version": affected_version,
                "is_used": is_used,  # Key differentiator from OSV agent!
                "recommendation": f"Update {affected_module} to a patched version",
                "references": references
            }

            oxo_vulns.append(oxo_vuln)
            logger.debug(f"✅ Created OXO vulnerability: {vuln_id} (used: {is_used})")

        logger.info(f"🎉 Conversion complete: {len(oxo_vulns)} OXO vulnerabilities created")
        return oxo_vulns

