#!/var/ossec/framework/python/bin/python3
import requests
from requests.auth import HTTPBasicAuth
import json
import sys
import logging
import os

from requests import packages

###################################
# Setup LOGGER
###################################
debug_enabled = True
info_enabled = True

# Set paths
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = '{0}/logs/integrations.log'.format(pwd)
logger = logging.getLogger(__name__)

# Set logging level
if debug_enabled:
    logger.setLevel(logging.DEBUG)
elif info_enabled:
    logger.setLevel(logging.INFO)
else:
    logger.setLevel(logging.WARNING)

# Create the logging file handler
fh = logging.FileHandler(log_file)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)
logger.debug('MidPoint - configured logger ...')

# Silence insecure request warning
requests.packages.urllib3.disable_warnings()

###################################
# Main FN
###################################


class MidPointClient:
    def __init__(self, base_url, username, password, verify_ssl=True):
        """
        Initialize the MidPoint API client.

        :param base_url: Base URL of the MidPoint server (e.g., 'http://localhost:8080/midpoint')
        :param username: Username for authentication
        :param password: Password for authentication
        :param verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url.rstrip('/')
        self.auth = HTTPBasicAuth(username, password)
        self.verify_ssl = verify_ssl

    def get_user_oid_by_username(self, username):
        """
        Retrieve a user's OID by their username.

        :param username: Username to search for
        :return: User's OID as a string
        :raises: Exception if user is not found or request fails
        """
        url = f"{self.base_url}/ws/rest/users/search"
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        payload = {
            "query": {
                "filter": {
                    "equal": {
                        "path": "name",
                        "value": username
                    }
                }
            }
        }

        response = requests.post(url, auth=self.auth, headers=headers, json=payload, verify=self.verify_ssl)
        response.raise_for_status()

        # The response will contain a user list object, with a user objet for each one.
        usersLs = response.json()

        if 'object' in usersLs:
            users = usersLs['object']
            # Match exactly one ouser
            if 'object' in users and len(usersLs['object']) != 1:
                user = users['object'][0]
                oid = user['oid']
                return oid
            else:
                raise Exception(f"User with username '{username}' not found. (list size is not 1, {len(usersLs['object'])})")
        else:
            raise Exception(f"User with username '{username}' not found.")

    def modify_user_attribute(self, oid, modification_type, path, value):
        """
        Modify an attribute of a specific user.

        :param oid: Object Identifier of the user
        :param modification_type: Type of modification ('add', 'replace', 'delete')
        :param path: Path of the attribute to modify (e.g., 'description')
        :param value: New value for the attribute
        :return: Response data as a JSON object
        :raises: requests.exceptions.HTTPError if the request fails
        """
        url = f"{self.base_url}/ws/rest/users/{oid}"
        headers = {
            'Content-Type': 'application/json'
        }

        # Construct the JSON payload
        payload = {
            "objectModification": {
                "itemDelta": {
                    "modificationType": modification_type,
                    "path": path,
                    "value": value
                }
            }
        }

        response = requests.patch(
            url,
            auth=self.auth,
            headers=headers,
            data=json.dumps(payload),
            verify=self.verify_ssl
        )
        response.raise_for_status()  # Raise an exception for HTTP errors

        # The API might not return JSON; handle accordingly
        if response.headers.get('Content-Type') == 'application/json':
            return response.json()
        else:
            return response.text


# Example usage:
if __name__ == "__main__":

    if len(sys.argv) < 4:
        logger.error("MidPoint - missing required arguments. Usage: script.py <source_path> <api_key> <hook_url>")
        raise IndexError("Missing required arguments. Usage: script.py <source_path> <api_key> <hook_url>")

    source_path = sys.argv[1]
    api_key = sys.argv[2]
    hook_url = sys.argv[3]

    logger.debug('MidPoint - source path: %s', source_path)

    with open(source_path, 'r') as alert_file:
        alert_json = json.load(alert_file)

    json_string = json.dumps(alert_json, indent=2)

    alert_level = alert_json['rule']['level']
    ruleid = alert_json['rule']['id']

    # Initialize the client (use env for credentials)
    client = MidPointClient(
        base_url='http://mp-server-svc/midpoint',
        username='api-client',
        password='User1pwd',  # TODO ! Replace with your actual password
        verify_ssl=False  # Set to True if using HTTPS with valid SSL certificates
    )

    # Extract the principal from the alert
    principal = alert_json['data']['principal']

    # Remove everything from the principal after the first comma
    username = principal.split(',')[0]
    logger.debug(f"MidPoint - Resolving username '{username}' to OID")

    try:
        oid = client.get_user_oid_by_username(username)
        logger.debug(f"MidPoint - Resolved username '{username}' to OID '{oid}'")
    except Exception as e:
        logger.error(f"MidPoint - Failed to get user OID for username '{username}': {e}")
        sys.exit(1)

    # Proceed to modify the user's activation status
    try:
        response_data = client.modify_user_attribute(oid, "replace", "activation/administrativeStatus", "DISABLED")
        logger.debug(f"MidPoint - Deactivated user with OID '{oid}'")
    except requests.exceptions.HTTPError as err:
        logger.error(f"MidPoint - Failed to modify user OID for username '{oid}': {err}")
        sys.exit(1)

