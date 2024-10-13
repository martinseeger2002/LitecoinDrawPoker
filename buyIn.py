import configparser
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from decimal import Decimal

# Load RPC credentials from RPC.conf
config = configparser.ConfigParser()
config.read('RPC.conf')

rpc_user = config['rpcconfig']['rpcuser']
rpc_password = config['rpcconfig']['rpcpassword']
rpc_host = config['rpcconfig']['rpchost']
rpc_port = config['rpcconfig']['rpcport']

# Create a connection to the Litecoin RPC server
def create_rpc_connection():
    return AuthServiceProxy(f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}")

rpc_connection = create_rpc_connection()

# Define the recipient address (update with your recipient address)
recipient_address = "<player pool address>"

def process_transaction(from_address, amount_ltc):
    try:
        # Set up transaction details
        to_address = recipient_address
        amount = Decimal(str(amount_ltc))
        amount_to_send = {to_address: float(amount)}
        
        # Create a raw transaction
        raw_tx = rpc_connection.createrawtransaction([], amount_to_send)
        
        # Fund the transaction, specifying the change address
        funded_tx = rpc_connection.fundrawtransaction(raw_tx, {"changeAddress": from_address})
        funded_tx_hex = funded_tx['hex']
        
        # Sign the transaction
        signed_tx = rpc_connection.signrawtransactionwithwallet(funded_tx_hex)
        if not signed_tx['complete']:
            print("Transaction signing incomplete.")
            return None
        signed_tx_hex = signed_tx['hex']
        
        # Broadcast the transaction
        txid = rpc_connection.sendrawtransaction(signed_tx_hex)
        print(f"Transaction broadcasted successfully! TXID: {txid}")
        return txid
        
    except JSONRPCException as e:
        print(f"An error occurred: {e.error['message']}")
        return None

# Example usage
if __name__ == "__main__":
    from_address = "<sender address>"  # Replace with your Litecoin address
    amount_ltc = 1.0  # The amount you want to send in Litecoin

    txid = process_transaction(from_address, amount_ltc)
    if txid:
        print(f"Transaction successful. TXID: {txid}")
    else:
        print("Transaction failed.")
