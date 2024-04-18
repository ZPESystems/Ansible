#!/usr/bin/env python

import argparse
import os
import sys
import logging
from logging.config import dictConfig

from common.nodegrid import Nodegrid
import config

LOG_LEVEL = logging.getLevelName(os.environ.get("LOG_LEVEL", config.LOG_LEVEL))
debug = config.DEBUG

dictConfig({
    "version": 1,
    "disable_existing_loggers": True,
    "formatters": {
        "default": {
            "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
        }
    },
    "handlers": {
        "console": {
            "level": LOG_LEVEL,
            "class": "logging.StreamHandler",
            "formatter": "default",
            "stream": "ext://sys.stdout",
        },
        "logs_file": {
            "level": LOG_LEVEL,
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "default",
            "filename": config.LOG_FILE,
            "maxBytes": 10000,
            "backupCount": 10,
            "delay": "True",
        },
        "debug_file": {
            "level": LOG_LEVEL,
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "default",
            "filename": f"{config.LOG_FILE.split('.')[0]}-debug.{config.LOG_FILE.split('.')[1]}",
            "maxBytes": 10000,
            "backupCount": 1,
            "delay": "True",
        }
    },
    "loggers": {
        "urllib3": {
            "handlers": ["console", "debug_file", "logs_file"] if debug else ["console", "logs_file"],
            "level": LOG_LEVEL,
            "propagate": False,
        },
    },
    "root": {
        "level": LOG_LEVEL,
        "handlers": ["console", "debug_file", "logs_file"] if debug else ["console", "logs_file"],
    }
})


def main(args):
    nodegrid = Nodegrid()
    nodegrid.login()
    nodegrid.configure_wireguard_tunnel()
    resp = nodegrid.check_peer(config.WIREGUARD_PEER_ID)

    if not resp:
        resp = nodegrid.add_peer(config.WIREGUARD_PEER_ID)
 
    logging.info(f"Peering info: {nodegrid.hub_info}")
    nodegrid.logout()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()    
    parser.add_argument('--conf-file', type=str, default='config.yaml')
    args = parser.parse_args()
    main(args)

