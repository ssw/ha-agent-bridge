import logging
import sys

import uvicorn

from .app import create_app
from .config import load
from .policy import PolicyError, parse

log = logging.getLogger("agent_bridge")


def main() -> int:
    settings = load()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        parse(settings.policy)
    except PolicyError as err:
        log.error("invalid policy: %s", err)
        return 1
    if not settings.ha_token:
        log.error("ha_token is not set")
        return 1
    uvicorn.run(
        create_app(settings),
        host=settings.listen_host,
        port=settings.listen_port,
        proxy_headers=False,
        server_header=False,
        log_level=settings.log_level,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
