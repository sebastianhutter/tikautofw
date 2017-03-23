#!/usr/bin/env python3
"""
    parse configuration for script.
    the whole config is done via env variables
"""

import os
from vault import Vault

class AutoFwConfig(object):

    def __init__(self):
        """
            initialize and check configuration
        """
        # rancher api service
        self.rancher_api_url=os.getenv('AUTOFW_RANCHER_API_URL','')
        self.rancher_api_key=os.getenv('AUTOFW_RANCHER_API_KEY','')
        self.rancher_api_secret=os.getenv('AUTOFW_RANCHER_API_SECRET','')

        # we use paramiko to access the ssh interface of the mikrotik
        # router. (with username and password)
        self.mikrotik_user=os.getenv('AUTOFW_MIKROTIK_USER','')
        self.mikrotik_pass=os.getenv('AUTOFW_MIKROTIK_PASS','')

        # mikrotik network config
        self.mikrotik_address=os.getenv('AUTOFW_MIKROTIK_ADDRESS','')
        self.mikrotik_ssh_port=os.getenv('AUTOFW_MIKROTIK_SSH_PORT','22')

        # approle key and secret id for vault
        self.vault_server=os.getenv('AUTOFW_VAULT_SERVER','')
        self.vault_role_id=os.getenv('AUTOFW_VAULT_ROLE_ID','')
        self.vault_secret_id=os.getenv('AUTOFW_VAULT_SECRET_ID','')

        # if all three values are specified we try to load the credentials for the
        # rancher api and the mikrotik firewall from the vault
        if self.vault_server and self.vault_role_id and self.vault_secret_id:
            try:
                # load the vault
                vault = Vault(self.vault_server, role_id=self.vault_role_id, secret_id=self.vault_secret_id)
                vault.request_access_token()

                # now load the different config values (if they exist)
                try:
                    self.rancher_api_key = vault.retrieve_secret('rancher/api/home/autofw','key')
                except:
                    pass
                try:
                    self.rancher_api_secret = vault.retrieve_secret('rancher/api/home/autofw','secret')
                except:
                    pass
                try:
                    self.mikrotik_user = vault.retrieve_secret('mikrotik/autofw','username')
                except:
                    pass
                try:
                    self.mikrotik_pass = vault.retrieve_secret('mikrotik/autofw','password')
                except:
                    pass
            except:
                pass
                self.rancher_api_key

                rancher/api/home/autofw

        # if no mikrotik address or no mikrotik credentials are specified
        # raise an error
        if not self.mikrotik_address or not self.mikrotik_user or not self.mikrotik_pass:
            raise Exception('Invalid Mikrotik Configuration')

        # if no rancher api config was given raise an error
        if not self.rancher_api_url or not self.rancher_api_key or not self.rancher_api_secret:
            raise Exception('Invalid Rancher Configuration')

        # docker labels for config
        # only check running containers?
        self.docker_check_running=os.getenv('AUTOFW_DOCKER_CHECK_RUNNING','true')
        # whats the container label which activates or disables the automatic fw settings
        self.docker_label_enable=os.getenv('AUTOFW_DOCKER_LABEL_ENABLE','cloud.hutter.autofw.enable')
        # nat lables
        # whats the label defining the nat rules
        self.docker_label_dstnat=os.getenv('AUTOFW_DOCKER_LABEL_NAT','cloud.hutter.autofw.ip.firewall.dstnat')
        # label for additional comment
        self.docker_label_dstnat_comment=os.getenv('AUTOFW_DOCKER_LABEL_NAT_COMMENT','cloud.hutter.autofw.ip.firewall.dstnat.comment')

        # dns labels
        # whats the label which holds the dns names
        self.docker_label_staticdns=os.getenv('AUTOFW_DOCKER_LABEL_DNS','cloud.hutter.autofw.ip.dns.static')
        self.docker_label_staticdns_comment=os.getenv('AUTOFW_DOCKER_LABEL_DNS_COMMENT','cloud.hutter.autofw.ip.dns.static.comment')

        # the comment which is used to filter for firewall rules
        self.mikrotik_comment=os.getenv('AUTOFW_MIKROTIK_COMMENT','generated by autofw')

        # loglevel
        self.loglevel = os.getenv('AUTOFW_LOGLEVEL','info')

        # time in seconds between runs
        self.schedule = os.getenv('AUTOFW_SCHEDULE','10')