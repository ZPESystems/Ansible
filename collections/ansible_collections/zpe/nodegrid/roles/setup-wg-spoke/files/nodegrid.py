import codecs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

import config
import requests

requests.packages.urllib3.disable_warnings()

from http import HTTPStatus
import logging
from loguru import logger


class Nodegrid():
    def __init__(self):
        self.url = f"{config.NODEGRID_URI}/{config.API_PREFIX}"
        self.session = ''
        self.public_key = ''
        self.private_key = ''
        self.hub_info = None
        self.wireguard = []
        self.wireguard_tunnel = {}
        self.wireguard_peers = []

    def login(self):
        url = f"{self.url}/Session"
        headers = {"Content-Type": "application/json", "accept": "application/json"}
        # data = '{ "username": "%s", "api_key": "%s"}' % (config.NODEGRID_USER, config.NODEGRID_KEY)
        data = {"username": config.NODEGRID_USER, "api_key": config.NODEGRID_KEY}
        try:
            response = requests.post(url, json=data, headers=headers, verify=False)
            if response.status_code == HTTPStatus.OK:
                self.session = str(response.json()["session"])
            else:
                raise Exception(f"{response.status_code} | {response.text}")
        except Exception as e:
            raise Exception(f"{str(e)}")

    def logout(self):
        url = f"{self.url}/Session"
        headers = {"ticket": self.session, "Content-Type": "application/json", "accept": "application/json"}
        try:
            response = requests.delete(url, headers=headers, verify=False)
        #            if response.status_code == HTTPStatus.OK:
        #            else:
        #                raise Exception(f"{response.status_code} | {response.text}")
        except Exception as e:
            raise Exception(f"{str(e)}")

    def get_wireguard_tunnels(self):
        url = f"{self.url}/network/wireguard"
        headers = {"ticket": self.session, "Content-Type": "application/json", "accept": "application/json"}
        try:
            response = requests.get(url, headers=headers, verify=False)
            if response.status_code == HTTPStatus.OK:
                self.wireguard = response.json()
            elif response.status_code == 401 and response.json()["message"] == "Invalid Session":
                self.login()
                self.get_wireguard_tunnels()
            else:
                raise Exception(f"{response.status_code} | {response.text}")
        except Exception as e:
            raise Exception(f"{e}")

    def get_wireguard_peers(self, wg_id):
        url = f"{self.url}/network/wireguard/{wg_id}/peers"
        headers = {"ticket": self.session, "Content-Type": "application/json", "accept": "application/json"}
        try:
            response = requests.get(url, headers=headers, verify=False)
            if response.status_code == HTTPStatus.OK:
                self.wireguard_peers = response.json()
            elif response.status_code == 401 and response.json()["message"] == "Invalid Session":
                self.login()
                self.get_wireguard_peers()
            else:
                raise Exception(f"{response.status_code} | {response.text}")
        except Exception as e:
            raise Exception(f"{e}")

    def get_wireguard_config(self, wg_id):
        url = f"{self.url}/network/wireguard/{wg_id}/interface"
        headers = {"ticket": self.session, "Content-Type": "application/json", "accept": "application/json"}
        try:
            response = requests.get(url, headers=headers, verify=False)
            if response.status_code == HTTPStatus.OK:
                self.wireguard_config = response.json()
                self.public_key = self.wireguard_config['public_key']
            elif response.status_code == 401 and response.json()["message"] == "Invalid Session":
                self.login()
                self.get_wireguard_config()
            else:
                raise Exception(f"{response.status_code} | {response.text}")
        except Exception as e:
            raise Exception(f"{e}")

    def check_peer(self, id):
        # logger.debug("Check Peer | peers: %s" % (self.wireguard_peers))
        if not self.hub_info:
            self.request_peer()
        logger.debug("Check Peer | hub_info: %s" % (self.hub_info))
        for apeer in self.wireguard_peers:
            if id == apeer["id"]:
                return apeer
        return None

    def add_peer(self, id):
        # self.configure_wireguard_tunnel()
        if not self.hub_info:
            self.request_peer()
        # logger.debug("Add Peer | hub_info: %s" % (self.hub_info))
        wg_id = config.WIREGUARD_IFACE_NAME
        url = f"{self.url}/network/wireguard/{wg_id}/peers"
        headers = {"ticket": self.session, "Content-Type": "application/json", "accept": "application/json"}
        peer = {"id": id, "peer_name": config.WIREGUARD_PEER_ID, "public_key": self.hub_info['public_key'],
                "description": "tunnel to hub", "external_address": self.hub_info['external_address'],
                "listening_port": self.hub_info['listening_port'], "keepalive": '21',
                "allowed_ips": self.hub_info['allowed_ips']}
        # logger.debug("Add Peer | peer: %s" % (peer))
        try:
            response = requests.post(url, headers=headers, json=peer, verify=False)
            if response.status_code == HTTPStatus.OK:
                return response

            elif response.status_code == 401 and response.json()["message"] == "Invalid Session":
                self.login()
                self.add_peer()
            else:
                raise Exception(f"{response.status_code} | {response.text}")
        except Exception as e:
            raise Exception(f"{e}")

    def generate_keys(self):
        self._private_key = X25519PrivateKey.generate()
        bytes_ = self._private_key.private_bytes(encoding=serialization.Encoding.Raw,
                                                 format=serialization.PrivateFormat.Raw,
                                                 encryption_algorithm=serialization.NoEncryption())
        self.private_key = codecs.encode(bytes_, 'base64').decode('utf8').strip()

        # derive public key
        self._public_key = self._private_key.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                                                       format=serialization.PublicFormat.Raw)
        self.public_key = codecs.encode(self._public_key, 'base64').decode('utf8').strip()
        # logger.debug("Private Key: %s" % (self.private_key))
        # logger.debug("Public Key: %s" % (self.public_key))

    def request_peer(self):
        try:
            url = f"{config.HUB_URI}/peers"
            headers = {"Content-Type": "application/json", "accept": "application/json"}
            data = {"id": config.WIREGUARD_PEER_ID, "peer_name": config.WIREGUARD_PEER_ID,
                    "public_key": self.public_key, "description": f"tunnel to {config.WIREGUARD_PEER_ID}"}

            response = requests.post(url, headers=headers, json=data, verify=False)
            if response.status_code == HTTPStatus.OK:
                self.hub_info = response.json()
            elif response.status_code == 401 and response.json()["message"] == "Invalid Session":
                self.login()
                self.request_peer()
            else:
                raise Exception(f"{response.status_code} | {response.text}")
        except Exception as e:
            raise Exception(f"{e}")

    def configure_wireguard_tunnel(self):
        try:
            self.get_wireguard_tunnels()
            for wg in self.wireguard:
                if 'id' in wg and wg['id'] == config.WIREGUARD_IFACE_NAME:
                    self.wireguard_tunnel = wg
                    self.get_wireguard_config(wg_id=self.wireguard_tunnel['id'])
                    self.get_wireguard_peers(wg_id=self.wireguard_tunnel['id'])
                    return

            self.generate_keys()
            self.request_peer()
            url = f"{self.url}/network/wireguard"
            headers = {"ticket": self.session, "Content-Type": "application/json", "accept": "application/json"}
            data = {"interface_name": config.WIREGUARD_IFACE_NAME, "interface_type": "client", "status": "enabled",
                    "internal_address": self.hub_info["peer_ip"], "keypair": "manual", "private_key": self.private_key,
                    "public_key": self.public_key}
            response = requests.post(url, headers=headers, json=data, verify=False)
            if response.status_code == HTTPStatus.OK:
                self.configure_wireguard_tunnel()
            elif response.status_code == 401 and response.json()["message"] == "Invalid Session":
                self.login()
                self.configure_wireguard_tunnel()
            else:
                raise Exception(f"{response.status_code} | {response.text}")
        except Exception as e:
            raise Exception(f"{e}")
