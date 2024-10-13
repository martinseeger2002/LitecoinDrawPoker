#!/usr/bin/env python3

"""
cashOut.py

This script signs and sends a Litecoin transaction from a specified address using the private key directly,
without importing the address into the Litecoin Core wallet.
"""

from decimal import Decimal
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der_canonize
import hashlib
import struct
import base58
import configparser
import segwit_addr

# Load RPC configuration from RPC.conf
config = configparser.ConfigParser()
config.read('RPC.conf')

rpc_user = config['rpcconfig']['rpcuser']
rpc_password = config['rpcconfig']['rpcpassword']
rpc_host = config['rpcconfig']['rpchost']
rpc_port = int(config['rpcconfig']['rpcport'])

# Global win_differential (should be set before calling send_litecoin)
win_differential = Decimal('0.0')

# Wallet information
from_address = "<player pool address>"  # Your Bech32 address
wif_private_key = "<player pool private key>"  # Your WIF private key

# Dev fee information
dev_fee_1_address = "<Dev Fee Address 1>"
dev_fee_2_address = "<Dev Fee Address 2>"
dev_fee_3_address = "<Dev Fee Address 3>"

dev_fee_1_percent = 0.01  # 1%
dev_fee_2_percent = 0.00  # 0.5%
dev_fee_3_percent = 0.00  # 0.3%

# Convert WIF private key to hex
def wif_to_privkey_hex(wif):
    # Decode WIF to get private key
    private_key_full = base58.b58decode_check(wif)
    # Remove version byte and compression flag (if present)
    if private_key_full[0] in [0xb0, 0x80]:  # Litecoin mainnet WIF versions
        if len(private_key_full) == 34:  # Compressed WIF key
            private_key_bytes = private_key_full[1:-1]
        else:  # Uncompressed WIF key
            private_key_bytes = private_key_full[1:]
    else:
        raise ValueError("Invalid WIF version byte.")
    return private_key_bytes.hex()

privkey_hex = wif_to_privkey_hex(wif_private_key)



def varint(n):
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)

def get_utxos(address):
    """
    Retrieve UTXOs for the given address using Litecoin Core RPC.
    """
    rpc_connection = AuthServiceProxy(f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}")
    utxos = []

    try:
        # Get the list of unspent transaction outputs for the address
        utxos_list = rpc_connection.listunspent(1, 9999999, [address])
        for utxo in utxos_list:
            utxo_info = {
                'txid': utxo['txid'],
                'vout': utxo['vout'],
                'value': int(Decimal(str(utxo['amount'])) * Decimal('1e8')),  # Convert LTC to litoshis
                'scriptPubKey': utxo['scriptPubKey'],
                'amount': Decimal(str(utxo['amount'])),
            }
            utxos.append(utxo_info)
            print(f"UTXO: {utxo_info}")  # Print UTXO details
    except JSONRPCException as e:
        print(f"An error occurred while retrieving UTXOs: {e.error['message']}")

    return utxos

def create_script_pubkey(address):
    if address.startswith('ltc1'):
        # Decode Bech32 address using segwit_addr module
        hrp = 'ltc'
        decoded = segwit_addr.decode(hrp, address)
        if decoded is None:
            raise ValueError("Invalid Bech32 address")
        witver, witprog = decoded

        # Create the scriptPubKey
        script_pubkey = bytes([0x00]) + varint(len(witprog)) + bytes(witprog)
    else:
        # Decode the address
        address_bytes = base58.b58decode_check(address)
        version = address_bytes[0]
        pubkey_hash = address_bytes[1:]
        # Build the scriptPubKey
        if version == 0x30:  # Litecoin P2PKH address
            script_pubkey = (
                b'\x76' +  # OP_DUP
                b'\xa9' +  # OP_HASH160
                bytes([len(pubkey_hash)]) +
                pubkey_hash +
                b'\x88' +  # OP_EQUALVERIFY
                b'\xac'    # OP_CHECKSIG
            )
        elif version == 0x32:  # Litecoin P2SH address
            script_pubkey = (
                b'\xa9' +  # OP_HASH160
                bytes([len(pubkey_hash)]) +
                pubkey_hash +
                b'\x87'    # OP_EQUAL
            )
        else:
            raise ValueError("Unknown address version")
    return script_pubkey

def create_raw_transaction(utxos, to_address, amount_satoshis, fee_satoshis, win_differential_satoshis):
    inputs = []
    outputs = {}
    total_input = 0

    # Calculate dev fees based on win_differential
    dev_fee_1_amount = int(win_differential_satoshis * dev_fee_1_percent)
    dev_fee_2_amount = int(win_differential_satoshis * dev_fee_2_percent)
    dev_fee_3_amount = int(win_differential_satoshis * dev_fee_3_percent)

    # Total amount needed (send amount + dev fees + transaction fee)
    total_needed = amount_satoshis + dev_fee_1_amount + dev_fee_2_amount + dev_fee_3_amount + fee_satoshis

    print(f"Total needed: {total_needed} litoshis")
    print(f"Available UTXOs: {utxos}")

    # Select UTXOs to cover the total amount needed
    for utxo in utxos:
        inputs.append({
            'txid': utxo['txid'],
            'vout': utxo['vout'],
            'scriptPubKey': utxo['scriptPubKey'],
            'amount': utxo['amount'],  # Decimal amount in LTC
            'value': utxo['value'],    # Amount in litoshis
        })
        total_input += utxo['value']
        print(f"Running total: {total_input} litoshis")
        if total_input >= total_needed:
            break

    if total_input < total_needed:
        print(f"Insufficient funds. Total input: {total_input}, Total needed: {total_needed}")
        raise Exception("Insufficient funds")

    # Outputs
    # vout 0: Recipient output
    outputs[to_address] = amount_satoshis

    # vout 1: Dev fee 1 output (if any)
    if dev_fee_1_amount > 0:
        outputs[dev_fee_1_address] = dev_fee_1_amount

    # vout 2: Dev fee 2 output (if any)
    if dev_fee_2_amount > 0:
        outputs[dev_fee_2_address] = dev_fee_2_amount

    # vout 3: Dev fee 3 output (if any)
    if dev_fee_3_amount > 0:
        outputs[dev_fee_3_address] = dev_fee_3_amount

    # vout 4: Change output (if any)
    change_satoshis = total_input - total_needed
    if change_satoshis > 0:
        outputs[from_address] = change_satoshis

    # Build the transaction object
    tx = {
        'version': 2,
        'locktime': 0,
        'inputs': inputs,
        'outputs': outputs,
    }

    return tx

def sighash_segwit(tx, input_index, script_code, value):
    """
    Compute the SegWit sighash for signing.
    """
    # Hash prevouts
    prevouts = b''.join([
        bytes.fromhex(txin['txid'])[::-1] + struct.pack("<I", txin['vout'])
        for txin in tx['inputs']
    ])
    hash_prevouts = hashlib.sha256(hashlib.sha256(prevouts).digest()).digest()

    # Hash sequence
    sequences = b''.join([
        struct.pack("<I", 0xffffffff) for txin in tx['inputs']
    ])
    hash_sequence = hashlib.sha256(hashlib.sha256(sequences).digest()).digest()

    # Hash outputs
    outputs = b''
    for addr, amount in tx['outputs'].items():
        outputs += struct.pack("<Q", amount)
        script_pubkey = create_script_pubkey(addr)
        outputs += varint(len(script_pubkey)) + script_pubkey
    hash_outputs = hashlib.sha256(hashlib.sha256(outputs).digest()).digest()

    txin = tx['inputs'][input_index]

    # Prepare the preimage
    preimage = b''
    preimage += struct.pack("<I", tx['version'])
    preimage += hash_prevouts
    preimage += hash_sequence
    preimage += bytes.fromhex(txin['txid'])[::-1]
    preimage += struct.pack("<I", txin['vout'])
    preimage += varint(len(script_code)) + script_code
    preimage += struct.pack("<Q", value)
    preimage += struct.pack("<I", 0xffffffff)  # sequence
    preimage += hash_outputs
    preimage += struct.pack("<I", tx['locktime'])
    preimage += struct.pack("<I", 1)  # SIGHASH_ALL

    # Double SHA256
    sighash = hashlib.sha256(hashlib.sha256(preimage).digest()).digest()
    return sighash

def get_compressed_public_key(vk):
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    x_bytes = x.to_bytes(32, byteorder='big')
    if y % 2 == 0:
        prefix = b'\x02'
    else:
        prefix = b'\x03'
    return prefix + x_bytes

def sign_transaction(tx, privkey_hex):
    privkey_bytes = bytes.fromhex(privkey_hex)
    privkey = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
    vk = privkey.get_verifying_key()
    public_key_bytes = get_compressed_public_key(vk)

    # Sign each input
    for index, txin in enumerate(tx['inputs']):
        # For P2WPKH, script_code is the standard scriptPubKey of P2PKH
        # script_code = OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
        pubkey_hash = hashlib.new('ripemd160', hashlib.sha256(public_key_bytes).digest()).digest()
        script_code = b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'

        # Amount in satoshis (litoshis)
        value = txin['value']

        # Compute the sighash
        sighash = sighash_segwit(tx, index, script_code, value)

        # Sign the sighash
        signature = privkey.sign_digest(sighash, sigencode=sigencode_der_canonize)
        signature += b'\x01'  # Append SIGHASH_ALL

        # Store the signature and public key in the witness
        txin['witness'] = [
            signature,
            public_key_bytes,
        ]

    return tx

def serialize_witness(tx):
    """
    Serialize the witness data for a SegWit transaction.
    """
    witness = b''
    for txin in tx['inputs']:
        if 'witness' in txin:
            witness_items = txin['witness']
            witness += varint(len(witness_items))
            for item in witness_items:
                witness += varint(len(item)) + item
        else:
            witness += b'\x00'
    return witness

def serialize_transaction(tx):
    """
    Serialize the full transaction, including the witness data.
    """
    # Version
    result = struct.pack("<I", tx['version'])

    # Marker and flag for SegWit
    result += b'\x00\x01'

    # Inputs
    result += varint(len(tx['inputs']))
    for txin in tx['inputs']:
        result += bytes.fromhex(txin['txid'])[::-1]
        result += struct.pack("<I", txin['vout'])
        result += varint(0)  # scriptSig is empty for P2WPKH
        result += struct.pack("<I", 0xffffffff)  # sequence

    # Outputs
    result += varint(len(tx['outputs']))
    for addr, amount in tx['outputs'].items():
        result += struct.pack("<Q", amount)
        script_pubkey = create_script_pubkey(addr)
        result += varint(len(script_pubkey)) + script_pubkey

    # Witness data
    result += serialize_witness(tx)

    # Locktime
    result += struct.pack("<I", tx['locktime'])

    return result

def broadcast_transaction(raw_tx_hex):
    """
    Broadcast the transaction to the network via Litecoin Core RPC.
    """
    rpc_connection = AuthServiceProxy(f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}")

    try:
        txid = rpc_connection.sendrawtransaction(raw_tx_hex)
        print(f"Transaction broadcasted successfully. TXID: {txid}")
        return txid
    except JSONRPCException as e:
        print(f"An error occurred: {e.error['message']}")
        return None

def send_litecoin(to_address, amount_ltc, win_differential_ltc):
    amount_satoshis = int(Decimal(amount_ltc) * Decimal('1e8'))
    win_differential_satoshis = int(Decimal(win_differential_ltc) * Decimal('1e8'))
    fee_ltc = Decimal('0.00003')  # Define the transaction fee in LTC (adjust as needed)
    fee_satoshis = int(fee_ltc * Decimal('1e8'))  # Convert fee to litoshis

    utxos = get_utxos(from_address)

    # Create the raw transaction
    tx = create_raw_transaction(utxos, to_address, amount_satoshis, fee_satoshis, win_differential_satoshis)

    # Sign the transaction
    tx_signed = sign_transaction(tx, privkey_hex)

    # Serialize the signed transaction
    raw_tx = serialize_transaction(tx_signed)
    raw_tx_hex = raw_tx.hex()

    # Print the raw transaction hex
    print(f"Raw transaction hex: {raw_tx_hex}")

    # Print win differential
    print(f"Win Differential: {win_differential_ltc} LTC")

    # Broadcast the transaction
    txid = broadcast_transaction(raw_tx_hex)

    if txid:
        print(f"Transaction successful. TXID: {txid}")
        print(f"Amount sent: {amount_ltc} LTC")
        print(f"Win Differential: {win_differential_ltc} LTC")
    else:
        print("Transaction failed.")

    return txid

def pubkey_to_p2wpkh_address(pubkey_bytes):
    # Hash the public key
    pubkey_hash = hashlib.new('ripemd160', hashlib.sha256(pubkey_bytes).digest()).digest()
    # Bech32 encode
    address = segwit_addr.encode('ltc', 0, pubkey_hash)
    return address

# Verify the derived address matches the expected address
if __name__ == "__main__":
    # Use the public key from the private key
    privkey_bytes = bytes.fromhex(privkey_hex)
    privkey = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
    vk = privkey.get_verifying_key()
    public_key_bytes = get_compressed_public_key(vk)

    # Generate the address from the public key
    derived_address = pubkey_to_p2wpkh_address(public_key_bytes)
    print(f"Derived Address: {derived_address}")

    # Compare with the expected address
    expected_address = from_address
    if derived_address == expected_address:
        print("The addresses match.")
    else:
        print("The addresses do not match. Please check the private key and address.")
        exit(1)

    # Example usage
    recipient_address = "<recipient address>"  # Replace with the player's Litecoin address
    amount_to_send = 0.01  # Amount in LTC
    win_differential = 0.00  # Set the win differential as needed
    send_litecoin(recipient_address, amount_to_send, win_differential)
