import random
import requests
from requests.auth import HTTPBasicAuth
import configparser
from functools import lru_cache
import os
import sys
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging
import time

def get_config_path():
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        return os.path.join(os.path.dirname(sys.executable), 'RPC.conf')
    else:
        # Running as script
        return os.path.join(os.path.dirname(__file__), 'RPC.conf')

# Read RPC configuration
config = configparser.ConfigParser()
config_path = get_config_path()
if not os.path.exists(config_path):
    raise FileNotFoundError(f"Config file not found: {config_path}")
config.read(config_path)

rpc_user = config['rpcconfig']['rpcuser']
rpc_password = config['rpcconfig']['rpcpassword']
rpc_host = config['rpcconfig']['rpchost']
rpc_port = config['rpcconfig']['rpcport']

# Define the deck of cards
suits = ['Hearts', 'Diamonds', 'Clubs', 'Spades']
ranks = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'Jack', 'Queen', 'King', 'Ace']
deck = [f"{rank} of {suit}" for suit in suits for rank in ranks]

# Define jokers
jokers = ['Joker 1', 'Joker 2']

# Prepare RPC request
url = f"http://{rpc_host}:{rpc_port}"
headers = {'content-type': 'application/json'}
auth = HTTPBasicAuth(rpc_user, rpc_password)

# Create a session with retry mechanism
def create_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.auth = HTTPBasicAuth(rpc_user, rpc_password)
    session.headers.update({'content-type': 'application/json'})
    return session

# Use LRU cache to store the session
@lru_cache(maxsize=1)
def get_session():
    return create_session()

def get_block_count():
    payload = {
        "method": "getblockcount",
        "params": [],
        "jsonrpc": "2.0",
        "id": 0,
    }
    session = get_session()
    try:
        response = session.post(url, json=payload, timeout=10)
        response.raise_for_status()
        return response.json()['result']
    except requests.RequestException as e:
        logging.error(f"Error in get_block_count: {e}")
        raise

def get_block_hash(height):
    payload = {
        "method": "getblockhash",
        "params": [height],
        "jsonrpc": "2.0",
        "id": 0,
    }
    session = get_session()
    try:
        response = session.post(url, json=payload, timeout=10)
        response.raise_for_status()
        return response.json()['result']
    except requests.RequestException as e:
        logging.error(f"Error in get_block_hash: {e}")
        raise

def extract_random_digits(hash_data):
    if len(hash_data) < 3:
        raise ValueError("Hash data too short")
    start = random.randint(0, len(hash_data) - 3)
    return int(hash_data[start:start+3], 16)

def deal_card():
    max_retries = 3
    retry_count = 0
    while retry_count < max_retries:
        try:
            max_height = get_block_count()
            random_height = random.randint(0, max_height)
            block_hash = get_block_hash(random_height)

            digits = extract_random_digits(block_hash)

            if 4057 <= digits <= 4058:
                return jokers[digits - 4057]
            elif digits < 4056:
                return deck[digits % 52]
        except (requests.RequestException, ValueError, RuntimeError) as e:
            retry_count += 1
            logging.warning(f"Error occurred (attempt {retry_count}/{max_retries}): {e}. Retrying...")
            # Clear the session cache to force a new connection
            get_session.cache_clear()
            # Add a small delay before retrying
            time.sleep(1)

    error_message = "Max retries reached. Unable to deal card."
    logging.error(error_message)
    raise RuntimeError(error_message)
