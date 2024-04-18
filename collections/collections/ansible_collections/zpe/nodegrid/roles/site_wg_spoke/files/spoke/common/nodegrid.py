import codecs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

import config
import requests
requests.packages.urllib3.disable_warnings()

from http import HTTPStatus
import logging

# requests verify ssl flag
VERIFY_SSL = False

class Nodegrid():
    def __init__(self):
        self.url =  f"{config.NODEGRID_URI}/{config.API_PREFIX}"
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
        data = { "username": config.NODEGRID_USER, "api_key": config.NODEGRID_KEY} 
        while True:
            try:
                response = requests.post(url, json=data, headers=headers, verify=VERIFY_SSL)
                match response.status_code:
                    case HTTPStatus.OK:
                        self.session = str(response.json()["session"])
                        logging.info(f"Log-in: Logged-in to nodegrid {url} successfully!")
                        return True
                    case HTTPStatus.UNAUTHORIZED:
                        if response.json()["message"].lower == "authentication failure":
                            logging.error(f"{response.status_code} | {response.text}")
                            logging.error("Invalid credentials to access Nodegrid API")
                            sys.exit(-1)
                        else:
                            logging.error(f"Log-in: {url} | {response.status_code} | {response.text}")
                            logging.error("Re-trying in 5s...")
                            sleep(5)
                    case _:
                        logging.error(f"Log-in: {url} | STATUS NOT PARSED | {response.status_code} | {response.text}")
                        logging.error("Re-trying in 5s...")
                        sleep(5)
            except Exception as e:
                logging.error(f"Log-in: {url} | {str(e)}")
                logging.error("Re-trying in 10s...")
                sleep(10)
    
    def logout(self):
        url = f"{self.url}/Session"
        headers = {"ticket": self.session, "Content-Type": "application/json", "accept": "application/json"}
        try:
            response = requests.delete(url, headers=headers, verify=VERIFY_SSL)
            logging.debug(f"Log-out: {url} | {response.status_code} | {response.text}")
        except Exception as e:
            logging.error(f"Logout: {str(e)}")

    def get_wireguard_tunnels(self):
        url = f"{self.url}/network/wireguard"
        headers = {"ticket": self.session, "Content-Type": "application/json", "accept": "application/json"}
        try:
            response = requests.get(url, headers=headers, verify=VERIFY_SSL)
            if response.status_code == HTTPStatus.OK:
                self.wireguard = response.json()
                return True
            elif response.status_code == HTTPStatus.UNAUTHORIZED and response.json()["message"].lower() == "invalid session":
                logging.debug(f"get_wireguard_tunnels: {url} | {response.status_code} | {response.text} | retrying login")
                self.login()
                return self.get_wireguard_tunnels()
            else:
                logging.error(f"get_wireguard_tunnels: {url} | {response.status_code} | {response.text}")
        except Exception as e:
            logging.exception(f"get_wireguard_tunnels: {url} | {str(e)}")
        return False

    def delete_wireguard_tunnel(self, interface):
        url = f"{self.url}/network/wireguard"
        headers = {"ticket": self.session, "Content-Type": "application/json", "accept": "application/json"}
        data = { "interfaces": [interface] }
        try:
            response = requests.delete(url, headers=headers, json=data, verify=VERIFY_SSL)
            if response.status_code == HTTPStatus.OK:
                return True
            elif response.status_code == HTTPStatus.UNAUTHORIZED and response.json()["message"].lower() == "invalid session":
                logging.debug(f"get_wireguard_tunnels: {url} | {response.status_code} | {response.text} | retrying login")
                self.login()
                return self.delete_wireguard_tunnel(interface)
            else:
                logging.error(f"delete_wireguard_tunnel: {url} | {response.status_code} | {response.text}")
        except Exception as e:
            logging.exception(f"delete_wireguard_tunnel: {url} | {str(e)}")
        return False

    def get_wireguard_peers(self, wg_id):
        url = f"{self.url}/network/wireguard/{wg_id}/peers"
        headers = {"ticket": self.session, "Content-Type": "application/json", "accept": "application/json"}
        try:
            response = requests.get(url, headers=headers, verify=VERIFY_SSL)
            if response.status_code == HTTPStatus.OK:
                self.wireguard_peers = response.json()
                return True
            elif response.status_code == HTTPStatus.UNAUTHORIZED and response.json()["message"].lower() == "invalid session":
                logging.debug(f"get_wireguard_peers: {url} | {response.status_code} | {response.text} | retrying login")
                self.login()
                return self.get_wireguard_peers()
            else:
                logging.error(f"get_wireguard_peers: {url} | {response.status_code} | {response.text}")
        except Exception as e:
            logging.exception(f"get_wireguard_peers: {str(e)}")
        return False
    
    def delete_wireguard_peer(self, wg_id, peer_id):
        url = f"{self.url}/network/wireguard/{wg_id}/peers"
        headers = {"ticket": self.session, "Content-Type": "application/json", "accept": "application/json"}
        data = {"peers": [peer_id]}
        try:
            response = requests.delete(url, headers=headers, verify=VERIFY_SSL)
            if response.status_code == HTTPStatus.OK:
                return True
            elif response.status_code == HTTPStatus.UNAUTHORIZED and response.json()["message"].lower() == "invalid session":
                logging.debug(f"delete_wireguard_peer: {url} | {response.status_code} | {response.text} | retrying login")
                self.login()
                return self.delete_wireguard_peer()
            else:
                logging.error(f"delete_wireguard_peer: {url} | {response.status_code} | {response.text}")
        except Exception as e:
            logging.exception(f"delete_wireguard_peer: {str(e)}")
        return False

    def get_wireguard_config(self, wg_id):
        url = f"{self.url}/network/wireguard/{wg_id}/interface"
        headers = {"ticket": self.session, "Content-Type": "application/json", "accept": "application/json"}
        try:
            response = requests.get(url, headers=headers, verify=VERIFY_SSL)
            if response.status_code == HTTPStatus.OK:
                self.public_key = str(response.json()["public_key"])
                self.wireguard_config = response.json()
                return True
            elif response.status_code == HTTPStatus.UNAUTHORIZED and response.json()["message"].lower() == "invalid session":
                logging.debug(f"get_wireguard_config: {url} | {response.status_code} | {response.text} | retrying login")
                self.login()
                return self.get_wireguard_config()
            else:
                logging.error(f"get_wireguard_config: {url} | {response.status_code} | {response.text}")
        except Exception as e:
            logging.exception(f"get_wireguard_config: {url} | {str(e)}")
        return False

    def check_peer(self, id):
        if not self.hub_info:
            self.request_peer()
        logging.debug("Check Peer | hub_info: %s" % (self.hub_info))
        for apeer in self.wireguard_peers:
            if id == apeer["id"]:
                logging.info(f"Wireguard {self.wg_id} | Deleting peer {id}")
                self.delete_wireguard_peer(self.wg_id, id)
                return None
        return None       

    def add_peer(self, id):
        #self.configure_wireguard_tunnel()
        if not self.hub_info:
            self.request_peer()
        logging.debug("Add Peer | hub_info: %s" % (self.hub_info))
        wg_id = config.WIREGUARD_IFACE_NAME
        url = f"{self.url}/network/wireguard/{wg_id}/peers"
        headers = {"ticket": self.session, "Content-Type": "application/json", "accept": "application/json"}
        peer = {
                "id": id,
                "peer_name": config.WIREGUARD_PEER_ID, 
                "public_key": self.hub_info['public_key'], 
                "description": "tunnel to hub", 
                "external_address": self.hub_info['external_address'], 
                "listening_port": self.hub_info['listening_port'], 
                "keepalive": '21', 
                "allowed_ips": self.hub_info['allowed_ips']
                }
        logging.debug("Add Peer | peer: %s" % (peer))
        try:
            response = requests.post(url, headers=headers, json=peer, verify=VERIFY_SSL)
            if response.status_code == HTTPStatus.OK:
                return response

            elif response.status_code == HTTPStatus.UNAUTHORIZED and response.json()["message"].lower() == "invalid session":
                self.login()
                return self.add_peer()
            else:
                logging.error(f"add_peer: {url} | {response.status_code} | {response.text}")
        except Exception as e:
            logging.exception(f"add_peer: {url} | {str(e)}")
        return ""

    def generate_keys(self):
        self._private_key = X25519PrivateKey.generate()
        bytes_ = self._private_key.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
        self.private_key = codecs.encode(bytes_, 'base64').decode('utf8').strip()
 
        # derive public key
        self._public_key = self._private_key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        self.public_key = codecs.encode(self._public_key, 'base64').decode('utf8').strip()
        logging.debug("Private Key: %s" % (self.private_key))
        logging.debug("Public Key: %s" % (self.public_key))

    def request_peer(self):
        try:
            url =  f"{config.HUB_URI}/peers"
            headers = {"Content-Type": "application/json", "accept": "application/json"}
            data = {"id":config.WIREGUARD_PEER_ID, "peer_name": config.WIREGUARD_PEER_ID , "public_key": self.public_key, "description": f"tunnel to {config.WIREGUARD_PEER_ID}"}

            logging.debug(f"request_peer {url} | {headers} | {data}")
            response = requests.post(url, headers=headers, json=data, verify=VERIFY_SSL)
            if response.status_code == HTTPStatus.OK:
                if response.json() != "":
                    self.hub_info = response.json()
                    logging.info(f"Info provided by Hub: {url} | {self.hub_info}")
                    return True
                else:
                    logging.error(f"Info provided by Hub is empty: {url} | {self.hub_info} ")
                    return False

            elif response.status_code == HTTPStatus.UNAUTHORIZED and response.json()["message"].lower() == "invalid session":
                self.login()
                return self.request_peer()
            else:
                logging.error(f"request_peer: {url} | {response.status_code} | {response.text}")
        except Exception as e:
            logging.exception(f"request_peer: {url} | {str(e)}")
        return False

    def configure_wireguard_tunnel(self):
        url = f"{self.url}/network/wireguard"
        try:
            self.get_wireguard_tunnels()
            for wg in self.wireguard:
                if 'id' in wg and wg['id'] == config.WIREGUARD_IFACE_NAME:
                    self.delete_wireguard_tunnel(wg['id'])
                    logging.info(f"Wireguard interface deleted: {wg['id']}")
                    break

            self.generate_keys()
            while True:
                if self.request_peer():
                    headers = {"ticket": self.session, "Content-Type": "application/json", "accept": "application/json"}
                    data = {
                            "interface_name": config.WIREGUARD_IFACE_NAME, 
                            "interface_type": "client", 
                            "status":"enabled", 
                            "internal_address": self.hub_info["peer_ip"], 
                            "keypair": "manual", 
                            "private_key": self.private_key, 
                            "public_key": self.public_key
                            }
                    response = requests.post(url, headers=headers, json=data, verify=VERIFY_SSL)
                    if response.status_code == HTTPStatus.OK:
                        logging.info("Wireguard VPN tunnel configured successfully!")
                        return True
                    elif response.status_code == HTTPStatus.UNAUTHORIZED and response.json()["message"].lower() == "invalid session":
                        logging.debug(f"configure_wireguard_tunnel: {url} | {response.status_code} | {response.text} | retrying login")
                        self.login()
                        return self.configure_wireguard_tunnel()
                    else:
                        logging.error(f"configure_wireguard_tunnel: {url} | {response.status_code} | {response.text}")
                logging.error("Error getting the info from the Hub. Retrying in 10s")
                sleep(10)
        except Exception as e:
            logging.exception(f"configure_wireguard_tunnel: {url} | {str(e)}")
        return False
