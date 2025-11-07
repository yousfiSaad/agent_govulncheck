"""Entry point for govulncheck agent module."""

import logging
from rich import logging as rich_logging

from agent.agent import GovulncheckAgent

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)


if __name__ == "__main__":
    logger.info("Starting GovulncheckAgent...")
    GovulncheckAgent.main()

