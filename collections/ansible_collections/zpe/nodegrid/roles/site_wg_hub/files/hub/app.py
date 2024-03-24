#!/usr/bin/env python3

import argparse
import gunicorn.app.base
from gunicorn import util
import os
import sys
import atexit
from ctypes import c_wchar_p

from globalstate import STATE
from common.nodegrid import Nodegrid
from resources.peers import Peers
import config

from flask import Flask, request
from flask_restful import Api
from multiprocessing import Manager, Array, Value, Lock
from multiprocessing.util import _exit_function
from ipaddress import IPv4Network
import logging
from logging.config import dictConfig

atexit.unregister(_exit_function)
LOG_LEVEL = logging.getLevelName(os.environ.get("LOG_LEVEL", config.LOG_LEVEL))
debug = config.DEBUG

dictConfig({
    "version": 1,
    "disable_existing_loggers": True,
    "formatters": {
        "default": {
            "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
        },
        "access": {
            "format": "%(message)s",
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
        },
        "access_file": {
            "level": LOG_LEVEL,
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "access",
            "filename": config.LOG_FILE_ACCESS,
            "maxBytes": 10000,
            "backupCount": 10,
            "delay": "True",
        }
    },
    "loggers": {
        "gunicorn.error": {
            "handlers": ["console"] if debug else ["console", "logs_file"],
            "level": LOG_LEVEL,
            "propagate": False,
        },
        "gunicorn.access": {
            "handlers": ["console"] if debug else ["console", "access_file"],
            "level": LOG_LEVEL,
            "propagate": False,
        },
        "app": {
            "handlers": ["console", "debug_file"] if debug else ["console", "logs_file"],
            "level": LOG_LEVEL,
            "propagate": False,
        },
        "urllib3": {
            "handlers": ["console", "debug_file"] if debug else ["console", "logs_file"],
            "level": LOG_LEVEL,
            "propagate": False,
        },
    },
    "root": {
        "level": LOG_LEVEL,
        "handlers": ["console", "debug_file"] if debug else ["console", "logs_file"],
    }
})

app = Flask(__name__)
api = Api(app)
api.add_resource(Peers, '/peers', '/peers/<string:id>')
nodegrid = Nodegrid()

def initialize():
    global STATE
    STATE['sessionlock'] = Lock()
    STATE['session'] = Value(c_wchar_p, '')
    STATE['lock'] = Manager().Lock()
    STATE['reserved'] = Manager().list(config.WIREGUARD_IP_RESERVED)
    nodegrid.login()
    if nodegrid.configure_wireguard_tunnel():
        app.logger.debug("Global STATE initialized")

# Custom Gunicorn application: https://docs.gunicorn.org/en/stable/custom.html
class HttpServer(gunicorn.app.base.BaseApplication):
    def __init__(self, app, exit_app_callback, options=None):
        self.options = options or {}
        self._exitAppCallback = exit_app_callback
        self.application = app
        super().__init__()

    def load_config(self):
        for key, value in self.options.items():
            if key in self.cfg.settings and value is not None:
                self.cfg.set(key.lower(), value)

    def load(self):
        return self.application

    def run(self):
        if self.cfg.daemon:
            if os.environ.get('NOTIFY_SOCKET'):
                msg = "Warning: you shouldn't specify `daemon = True`" \
                      " when launching by systemd with `Type = notify`"
                print(msg, file=sys.stderr, flush=True)
                logging.warning(msg)

            util.daemonize(self.cfg.enable_stdio_inheritance)
        super().run()

    @staticmethod
    def exitWorker(arbiter, worker):
        # worker.app provides us with a reference to "self", and we can call the 
        # exit callback with the object created by the createAppCallback:
        self = worker.app
        self._exitAppCallback()
    
    @staticmethod
    def exitGunicorn(arbiter):
        self = arbiter.app
        self._exitAppCallback()

# Function to execute on Gunicorn on_exit
def exitGunicorn():
    nodegrid.logout()

if __name__ == '__main__':
    global STATE

    parser = argparse.ArgumentParser()    
    parser.add_argument('--num-workers', type=int, default=4)
    parser.add_argument('--port', type=str, default='8080')
    parser.add_argument('--daemon', default=False, action=argparse.BooleanOptionalAction)
    parser.add_argument('--pid', type=str, default=None)
    args = parser.parse_args()
    options = {
        'bind': '%s:%s' % ('0.0.0.0', args.port),
        'workers': args.num_workers,
        'on_exit': HttpServer.exitGunicorn,
        'daemon': args.daemon,
        'pidfile': args.pid,
    }
    
    initialize()
    HttpServer(app, exitGunicorn, options).run()
