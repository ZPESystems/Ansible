from globalstate import STATE
from time import sleep
from multiprocessing import Manager, Array
import config
import requests
requests.packages.urllib3.disable_warnings()
from http import HTTPStatus
import logging
import sys

class Nodegrid():
    def __init__(self):
        self.url =  f"{config.NODEGRID_URI}{config.API_PREFIX}"
        self.wireguard = []
        self.wireguard_tunnel = {}
        self.wireguard_peers = []

    def login(self):
        global STATE
        lock = STATE['sessionlock'].acquire(block=False)
        if not lock:
            while STATE['session'].value == '':
                sleep(1)
            return True
        if lock:
            STATE['session'].value = ''
            url = f"{self.url}/Session"
            headers = {"Content-Type": "application/json", "accept": "application/json"}
            data = { "username": config.NODEGRID_USER, "api_key": config.NODEGRID_KEY} 
            while True:
                try:
                    response = requests.post(url, json=data, headers=headers, verify=False)
                    match response.status_code:
                        case HTTPStatus.OK:
                            STATE['session'].value = str(response.json()["session"])
                            logging.debug(f"Log-in: Logging to nodegrid {url} successfull!")
                            break
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
        STATE['sessionlock'].release()
        return True
    
    def logout(self):
        global STATE
        url = f"{self.url}/Session"
        headers = {"ticket": STATE['session'].value, "Content-Type": "application/json", "accept": "application/json"}
        try:
            response = requests.delete(url, headers=headers, verify=False)
            logging.debug(f"Log-out: {url} | {response.status_code} | {response.text}")
        except Exception as e:
            logging.error(f"Logout: {str(e)}")

    def get_wireguard_tunnels(self):
        global STATE
        url = f"{self.url}/network/wireguard"
        headers = {"ticket": STATE['session'].value, "Content-Type": "application/json", "accept": "application/json"}
        try:
            response = requests.get(url, headers=headers, verify=False)
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

    def get_wireguard_peers(self, wg_id):
        global STATE
        url = f"{self.url}/network/wireguard/{wg_id}/peers"
        headers = {"ticket": STATE['session'].value, "Content-Type": "application/json", "accept": "application/json"}
        try:
            response = requests.get(url, headers=headers, verify=False)
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
    
    def get_wireguard_config(self, wg_id):
        global STATE
        url = f"{self.url}/network/wireguard/{wg_id}/interface"
        headers = {"ticket": STATE['session'].value, "Content-Type": "application/json", "accept": "application/json"}
        try:
            response = requests.get(url, headers=headers, verify=False)
            if response.status_code == HTTPStatus.OK:
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
    
    def update_peer(self, peer):
        global STATE
        wg_id = config.WIREGUARD_IFACE_NAME
        url = f"{self.url}/network/wireguard/{wg_id}/peers"
        headers = {"ticket": STATE['session'].value, "Content-Type": "application/json", "accept": "application/json"}
        try:
            data = {"peers": [peer["id"]]}
            response = requests.delete(url, headers=headers, json=data, verify=False)
            if response.status_code == HTTPStatus.OK:
                return self.add_peer(peer)
            elif response.status_code == HTTPStatus.UNAUTHORIZED and response.json()["message"].lower() == "invalid session":
                logging.debug(f"update_peer: {url} | {response.status_code} | {response.text} | retrying login")
                self.login()
                return self.update_peer(peer)
            else:
                logging.error(f"update_peer: {response.status_code} | {response.text}")
        except Exception as e:
            logging.exception(f"update_peer: {str(e)}")
        return ""

    def check_peer(self, peer):
        self.configure_wireguard_tunnel()
        wg_id = config.WIREGUARD_IFACE_NAME
        for apeer in self.wireguard_peers:
            if peer["id"] == apeer["id"]:
                if peer["public_key"] != apeer["public_key"]:
                    logging.info("Different public_keys: %s | %s" % (peer,apeer))
                    apeer["public_key"] = peer["public_key"]
                    self.update_peer(apeer)
                resp = {
                        "allowed_ips": config.WIREGUARD_IFACE_IP,
                        "public_key": self.wireguard_config["public_key"],
                        "external_address": self.wireguard_config["external_address"],
                        "listening_port": self.wireguard_config["listening_port"],
                        "peer_ip": apeer["allowed_ips"]
                        }
                return resp
        return None       

    def add_peer(self, peer):
        #self.configure_wireguard_tunnel()
        wg_id = config.WIREGUARD_IFACE_NAME
        url = f"{self.url}/network/wireguard/{wg_id}/peers"
        headers = {"ticket": STATE['session'].value, "Content-Type": "application/json", "accept": "application/json"}
        try:
            response = requests.post(url, headers=headers, json=peer, verify=False)
            if response.status_code == HTTPStatus.OK:
                resp = {
                        "allowed_ips": config.WIREGUARD_IFACE_IP,
                        "public_key": self.wireguard_config["public_key"],
                        "external_address": self.wireguard_config["external_address"],
                        "listening_port": self.wireguard_config["listening_port"],
                        "peer_ip": peer["allowed_ips"]
                        }
                logging.debug("Add Peer request: %s | answer: %s" % (peer,resp))
                return resp

            elif response.status_code == HTTPStatus.UNAUTHORIZED and response.json()["message"].lower() == "invalid session":
                logging.debug(f"add_peer: {url} | {response.status_code} | {response.text} | retrying login")
                self.login()
                return self.add_peer(peer)
            else:
                logging.error(f"add_peer: {url} | {response.status_code} | {response.text}")
        except Exception as e:
            logging.exception(f"add_peer: {url} | {str(e)}")
        return ""

    def configure_wireguard_tunnel(self):
        global STATE
        url = f"{self.url}/network/wireguard"
        try:
            self.get_wireguard_tunnels()
            for wg in self.wireguard:
                if 'id' in wg and wg['id'] == config.WIREGUARD_IFACE_NAME:
                    self.wireguard_tunnel = wg 
                    self.get_wireguard_config(wg_id = self.wireguard_tunnel['id'])
                    self.get_wireguard_peers(wg_id = self.wireguard_tunnel['id'])
                    for peer in self.wireguard_peers:
                        if "allowed_ips" in peer:
                            STATE['reserved'].append(peer['allowed_ips'].split("/")[0])
                    return

            headers = {"ticket": STATE['session'].value, "Content-Type": "application/json", "accept": "application/json"}
            data = {
                    "interface_name": config.WIREGUARD_IFACE_NAME, 
                    "interface_type": "server",
                    "status": "enabled",
                    "internal_address": config.WIREGUARD_IFACE_IP,
                    "listening_port": str(config.WIREGUARD_IFACE_PUBLIC_PORT),
                    "keypair": "auto", 
                    "external_address": config.WIREGUARD_IFACE_PUBLIC_IP
                    }

            response = requests.post(url, headers=headers, json=data, verify=False)
            if response.status_code == HTTPStatus.OK:
                self.configure_wireguard_tunnel()
                return True
            elif response.status_code == HTTPStatus.UNAUTHORIZED and response.json()["message"].lower() == "invalid session":
                logging.debug(f"configure_wireguard_tunnel: {url} | {response.status_code} | {response.text} | retrying login")
                self.login()
                return self.configure_wireguard_tunnel()
            else:
                logging.error(f"configure_wireguard_tunnel: {url} | {response.status_code} | {response.text}")
        except Exception as e:
            logging.exception(f"configure_wireguard_tunnel: {url} | {str(e)}")
        return False
