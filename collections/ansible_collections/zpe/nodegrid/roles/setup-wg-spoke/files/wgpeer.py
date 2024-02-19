#!/usr/bin/env python

import argparse
import os
import sys
import logging
from loguru import logger

from common.nodegrid import Nodegrid
import config

LOG_LEVEL = logging.getLevelName(os.environ.get("LOG_LEVEL", config.LOG_LEVEL))
JSON_LOGS = True if os.environ.get("JSON_LOGS", "0") == "1" else False


class InterceptHandler(logging.Handler):
    def emit(self, record):
        # get corresponding Loguru level if it exists
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # find caller from where originated the logged message
        frame, depth = sys._getframe(6), 6
        while frame and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.bind(name=record.name).opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


def main(args):
    nodegrid = Nodegrid()
    nodegrid.login()
    nodegrid.configure_wireguard_tunnel()
    resp = nodegrid.check_peer(config.WIREGUARD_PEER_ID)

    if not resp:
        resp = nodegrid.add_peer(config.WIREGUARD_PEER_ID)

    # logger.debug(nodegrid.hub_info)
    nodegrid.logout()


if __name__ == '__main__':
    intercept_handler = InterceptHandler()
    logging.root.setLevel(LOG_LEVEL)
    logger.remove()

    seen = set()
    for name in [
        *logging.root.manager.loggerDict.keys(),
        "requests.packages.urllib3",
    ]:
        if name not in seen:
            seen.add(name.split(".")[0])
            logging.getLogger(name).handlers = [intercept_handler]

    logger.configure(handlers=[{"sink": sys.stdout, "serialize": JSON_LOGS}])

    parser = argparse.ArgumentParser()
    parser.add_argument('--conf-file', type=str, default='config.yaml')
    args = parser.parse_args()
    main(args)