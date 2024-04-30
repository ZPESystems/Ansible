from json import dumps, loads
from flask import jsonify
from flask_restful import Resource, request
from http import HTTPStatus
from marshmallow import Schema, fields, ValidationError
from ipaddress import IPv4Network
from globalstate import STATE
import config
import os
import sys
from common.nodegrid import Nodegrid
import logging

try:
    network = IPv4Network(config.WIREGUARD_LAN, strict=False)
except Exception as e:
    logging.exception(f"Peers network config: | {str(e)}")
    sys.exit(-1)

nodegrid = Nodegrid()

class PeerSchema(Schema):
    id = fields.String(required=True)
    peer_name = fields.String(required=True)
    public_key = fields.String(required=True)
    keepalive = fields.String(required=False, load_default='21')
    description = fields.String(required=True)

def get_ip():
    global STATE
    STATE['lock'].acquire()
    nextip = next(str(ip) for ip in network.hosts() if str(ip) not in STATE['reserved'])
    STATE['reserved'].append(nextip)
    STATE['lock'].release()
    return f"{nextip}/32"

class Peer():
    def __init__(id, args, allowed_ips):
        self.id = args['id']
        self.peer_name = args['peer_name']
        self.allowed_ips = allowed_ips
        self.public_key = args['public_key']
        self.keepalive = args['keepalive']
        self.description = args['description']

class Peers(Resource):
    def post(self):
        request_data = request.json
        schema = PeerSchema()
        try:
            # Validate request body against schema data types
            result = schema.load(request_data)
        except ValidationError as err:
            # Return a nice message if validation fails
            return err.messages, HTTPStatus.BAD_REQUEST

        resp = nodegrid.check_peer(result)

        if not resp:
            result['allowed_ips'] = get_ip()
            resp = nodegrid.add_peer(result)
            if resp == "":
                logging.error(f"Peers post error on adding a new peer | IP allocated {result['allowed_ips']}")
                return resp, HTTPStatus.INTERNAL_SERVER_ERROR
        # Send data back as JSON
        logging.info(f"Peer request: {request_data} | Result: {resp}")
        return resp, HTTPStatus.OK
