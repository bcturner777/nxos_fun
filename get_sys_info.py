import requests, urllib3
# define the path for importing the vault.py module
#   The vault.py module will also import hvac, os, requests, and dnacentersdk
import sys
sys.path.append('/Users/blaturne/DevNetCode/devasc-exam/vault/')
# import vault.py specific functions and variables that exists in upstream vault directory
from vault import vault_auth, nxos_vault_r_secret, vault_unseal_key, vault_role_id, vault_secret_id

vault_mount_point = 'kv-v1'
nxos_vault_path = '/devnet/nx-os/sbx'

def nxos_api_access():
    """
    This function will Authenticate against Cisco NX-OS Sandbox switch
    using the secret creds provided securely by Vault
    """    
    creds = nxos_vault_r_secret(nxos_vault_path, vault_mount_point)
    # Disable Self-Signed Cert warning for demo
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    # Assign requests.Session instance to session variable
    session = requests.Session()
    # Define URL and PAYLOAD variables
    URL = "https://sbx-nxos-mgmt.cisco.com/api/aaaLogin.json"
    PAYLOAD = {
            "aaaUser": {
                "attributes": {
                "name": (creds[0]),
                "pwd": (creds[1])
                }
              }
            }
    # Obtain an authentication cookie
    session.post(URL,json=PAYLOAD,verify=False)
    # Define SYS_URL variable
    SYS_URL = "https://sbx-nxos-mgmt.cisco.com/api/mo/sys.json"
    # Obtain system information by making session.get call
    # then convert it to JSON format then filter to system attributes
    sys_info = session.get(SYS_URL,verify=False).json()["imdata"][0]["topSystem"]["attributes"]
    # Print hostname, serial nmber, uptime and current state information
    # obtained from the NXOSv9k
    print("HOSTNAME:", sys_info["name"])
    print("SERIAL NUMBER:", sys_info["serial"])
    print("UPTIME:", sys_info["systemUpTime"])

if __name__ == '__main__':
    vault_auth()
    nxos_api_access()
