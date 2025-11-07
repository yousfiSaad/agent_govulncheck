"""Main OXO agent for govulncheck vulnerability scanning."""

import logging
from pathlib import Path
from typing import Dict, Optional

from rich import logging as rich_logging
from ostorlab.agent import agent
from ostorlab.agent.message import message as m

from agent.govulncheck_wrapper import GovulncheckWrapper

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)
logger.setLevel("DEBUG")


class GovulncheckAgent(agent.Agent):
    """OXO agent for Go vulnerability scanning using govulncheck."""
    
    def __init__(self, agent_definition, *args, **kwargs):
        """Initialize agent.
        
        Args:
            agent_definition: Agent definition from OXO
        """
        super().__init__(agent_definition, *args, **kwargs)
        self.govulncheck = GovulncheckWrapper()
        logger.info("GovulncheckAgent initialized")
    
    def start(self) -> None:
        """Start the agent.
        
        OXO's orchestrator waits for services (including message queue) to be healthy
        before starting agents and injecting assets, so we don't need to wait here.
        """
        logger.info("GovulncheckAgent started")
    
    def process(self, message: m.Message) -> None:
        """Process incoming asset message.

        Args:
            message: OXO message containing asset to scan
        """
        # OXO Message class uses 'selector' not 'protobuf_type'
        selector = message.selector
        logger.info(f"📨 Received message with selector: {selector}")
        logger.debug(f"📄 Message data keys: {list(message.data.keys()) if message.data else 'None'}")

        # Handle File asset (go.mod or go.sum)
        # Selector format: v3.asset.file or v3.asset.file[path=**/go.mod]
        if selector.startswith("v3.asset.file"):
            file_path = message.data.get("path")
            logger.info(f"📁 Processing file asset: {file_path}")
            
            if file_path:
                self._scan_file(file_path)
            else:
                logger.warning("⚠️  File message received but no path provided in message.data")
                logger.debug(f"📄 Full message data: {message.data}")

        # Handle Domain asset (could scan Go modules from URLs)
        elif selector.startswith("v3.asset.domain"):
            # Future: Could fetch and scan Go modules from domain
            logger.info("🌐 Domain scanning not implemented yet")

        # Handle Link asset
        elif selector.startswith("v3.asset.link"):
            # Future: Could fetch Go modules from URLs
            logger.info("🔗 Link scanning not implemented yet")
        else:
            logger.debug(f"⏭️  Unhandled message selector: {selector}")
    
    def _scan_file(self, file_path: str) -> None:
        """Scan a file (go.mod or go.sum).

        Args:
            file_path: Path to file to scan
        """
        logger.info(f"🔍 Starting file scan for: {file_path}")

        # Validate file path
        file_path_obj = Path(file_path)
        if not file_path_obj.exists():
            logger.error(f"❌ File not found: {file_path}")
            return

        logger.info(f"✅ File exists: {file_path_obj.resolve()}")

        # Check if it's a Go module file
        if not file_path.endswith(("go.mod", "go.sum")):
            logger.warning(f"⚠️  File {file_path} is not a Go module file (go.mod or go.sum)")
            return

        logger.info("✅ File type validation passed")

        # Run govulncheck scan
        logger.info("🚀 Calling govulncheck.scan_file()...")
        result = self.govulncheck.scan_file(file_path)

        logger.info(f"📊 Scan result received: exit_code={result.get('exit_code', 'N/A')}")
        logger.debug(f"📄 Full scan result: {result}")

        if result.get("error"):
            logger.error(f"💥 Scan failed with error: {result['error']}")
            return

        # Convert to OXO format
        logger.info("🔄 Converting to OXO format...")
        oxo_vulns = self.govulncheck.convert_to_oxo_format(result)

        logger.info(f"📋 Conversion complete: {len(oxo_vulns)} vulnerabilities found")

        # Report vulnerabilities
        reported_count = 0
        for i, vuln in enumerate(oxo_vulns, 1):
            vuln_id = vuln.get('vulnerability_id', 'UNKNOWN')
            is_used = vuln.get('is_used', False)
            logger.info(f"📤 Reporting vuln {i}/{len(oxo_vulns)}: {vuln_id} (used: {is_used})")
            self._report_vulnerability(vuln, file_path)
            reported_count += 1

        logger.info(f"✅ Scan complete. Successfully reported {reported_count} vulnerabilities")
    
    def _report_vulnerability(
        self,
        vuln: Dict,
        file_path: str
    ) -> None:
        """Report vulnerability to OXO.

        Args:
            vuln: Vulnerability dictionary in OXO format
            file_path: Path to scanned file
        """
        vuln_id = vuln["vulnerability_id"]
        affected_pkg = vuln["affected_package"]
        is_used = vuln["is_used"]

        logger.info(f"📤 Building OXO vulnerability report for: {vuln_id} (used: {is_used})")

        # Build vulnerability metadata
        metadata = {
            "vulnerability_id": vuln_id,
            "affected_package": affected_pkg,
            "affected_version": vuln["affected_version"],
            "is_used": is_used,
            "cvss_score": vuln.get("cvss_score"),
            "recommendation": vuln["recommendation"]
        }

        logger.debug(f"📋 Metadata: {metadata}")

        # Build vulnerability message data
        vulnerability_data = {
            "title": vuln["title"],
            "short_description": vuln["description"][:200] if vuln["description"] else "",
            "description": vuln["description"],
            "risk_rating": vuln["severity"],
            "references": [{"url": ref} for ref in vuln.get("references", [])],
            "metadata": metadata
        }

        logger.debug(f"📄 Full vulnerability data: {vulnerability_data}")

        # Report to OXO
        logger.info(f"🚀 Emitting v3.report.vulnerability for {vuln_id} in {affected_pkg}")
        try:
            self.emit("v3.report.vulnerability", vulnerability_data)
            logger.info(f"✅ Successfully emitted vulnerability report for {vuln_id}")
        except Exception as e:
            logger.error(f"❌ Failed to emit vulnerability report: {e}", exc_info=True)


if __name__ == "__main__":
    logger.info("starting agent ...")
    GovulncheckAgent.main()

