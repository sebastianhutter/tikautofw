#!/usr/bin/env python
import requests
import json

class Vault (object):
    """
        simple class to authenticate against hashicorp
        vault and get data.

        only supports approle atm
    """

    def __init__(self, vault_url, role_id, secret_id):
        """
            initialise vault connection
        """

        self.vault_url = vault_url
        self.role_id = role_id
        self.secret_id = secret_id
        self.auth_endpoint = '/v1/auth/approle/login'

    def request_access_token(self):
        """
            request access token
        """
        # now try to connect to the vault service and authenticate
        r = requests.post(self.vault_url + self.auth_endpoint, data=json.dumps({'role_id': self.role_id, 'secret_id': self.secret_id}))
        r.raise_for_status()

        # if the connection succeded safe the access token
        self.access_token = r.json()['auth']['client_token']


    def retrieve_secret(self, secret, key):
        """
            retrieve the value of the specified key of the secret

            specify the secret path after /v1/secret/ (e.g. for the mikrotik user mikrotik/autofw)
        """
        try:
            r = requests.get(self.vault_url + '/v1/secret/' + secret, headers = {"X-Vault-Token":self.access_token})
            r.raise_for_status()
            data = r.json()['data']
            if key in data:
                return data[key]
            else:
                raise NameError
        except:
            raise
