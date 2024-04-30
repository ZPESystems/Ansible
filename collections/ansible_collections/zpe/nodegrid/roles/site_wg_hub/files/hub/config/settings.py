import yaml

def load_conf_file(config_file="config.yaml"):
   with open(config_file, "r") as f:
       config = yaml.safe_load(f)
   return config

config = load_conf_file()

class BaseConfig():
    API_PREFIX = config['API_PREFIX']
    TESTING = False
    DEBUG = False

class DevConfig(BaseConfig):
    FLASK_ENV = config['FLASK_ENV']
    DEBUG = config['DEBUG']
    LOG_LEVEL = config['LOG_LEVEL']
    LOG_FILE = config['LOG_FILE']
    LOG_FILE_ACCESS = config['LOG_FILE_ACCESS']
    NODEGRID_URI = config['NODEGRID_URI']
    NODEGRID_USER = config['NODEGRID_USER']
    NODEGRID_KEY = config['NODEGRID_KEY']
    WIREGUARD_IFACE_NAME = config['WIREGUARD_IFACE_NAME']
    WIREGUARD_LAN = config['WIREGUARD_LAN']
    WIREGUARD_IFACE_IP = config['WIREGUARD_IFACE_IP']
    WIREGUARD_IP_RESERVED = [anip.split("/")[0] for anip in config['WIREGUARD_IP_RESERVED']]
    WIREGUARD_IFACE_PUBLIC_IP = config['WIREGUARD_IFACE_PUBLIC_IP']
    WIREGUARD_IFACE_PUBLIC_PORT = config['WIREGUARD_IFACE_PUBLIC_PORT']
