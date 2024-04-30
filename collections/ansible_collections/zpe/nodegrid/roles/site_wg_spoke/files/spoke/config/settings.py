#import yaml
from configparser import ConfigParser

def load_conf_file(config_file="config.ini"):
   config = ConfigParser()
   with open(config_file, "r") as f:
       config.read_file(f)
   return config['spoke']

config = load_conf_file()

class BaseConfig():
    API_PREFIX = config['API_PREFIX']
    TESTING = False
    DEBUG = False

class DevConfig(BaseConfig):
    DEBUG = config['DEBUG']
    LOG_FILE = config['LOG_FILE']
    LOG_LEVEL = config['LOG_LEVEL']
    NODEGRID_URI = config['NODEGRID_URI']
    NODEGRID_USER = config['NODEGRID_USER']
    NODEGRID_KEY = config['NODEGRID_KEY']
    WIREGUARD_IFACE_NAME = config['WIREGUARD_IFACE_NAME']
    WIREGUARD_PEER_ID = config['WIREGUARD_PEER_ID']
    HUB_URI = config['HUB_URI']

