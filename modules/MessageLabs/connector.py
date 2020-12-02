#!/usr/bin/env python3
# -*- coding: utf8 -*-

import logging
import sys
import os
import json
import msal
import requests

class MLabsConnector:
    'MessageLabs connector via Graph API'

    def __init__(self, cfg):
        self.logger = logging.getLogger('workflows.' + __name__)
        self.cfg = cfg
        self.proxy = self.cfg.get('MessageLabs', 'proxy')
        self.proxies = {
            'http': self.proxy,
            'https': self.proxy
        }
        self.token = self.getToken()

    def getToken(self):
        self.logger.debug('%s. getToken starts', __name__)
        try:

            authority = self.cfg.get('MessageLabs', 'authority')
            client_id = self.cfg.get('MessageLabs', 'client_id')
            scope = self.cfg.get('MessageLabs', 'scope')
            secret = self.cfg.get('MessageLabs', 'secret')

            app = msal.ConfidentialClientApplication(
                client_id, authority=authority,
                client_credential=secret, verify=False, proxies=self.proxies
            )

            result = None
            result = app.acquire_token_silent(scope, account=None)

            if not result:
                result = app.acquire_token_for_client(scopes=scope)

            # error if token is not found
            return result['access_token']

        except Exception as e:
            self.logger.error('Failed to authenticate', exc_info=True)
            self.logger.error("MessageLabs: {}".format(result.get("error")), exc_info=True)
            self.logger.error("MessageLabs: {}".format(result.get("error_description")), exc_info=True)
            self.logger.error("MessageLabs: {}".format(result.get("correlation_id")), exc_info=True)
            raise

    def scan(self, link_to_load):

        self.logger.debug('%s.scan starts', __name__)

        try:
            graph_data = requests.get(link_to_load, headers={'Authorization': 'Bearer ' + self.token, 'Prefer': 'outlook.body-content-type=text'}, verify=False, proxies=self.proxies).json()
            emails = graph_data['value']
            next_link = ""
            if '@odata.nextLink' in graph_data:
                self.logger.debug("MessageLabs: Writing nextLink(loop) to the tracker file...")
                next_link = graph_data["@odata.nextLink"]
            elif '@odata.deltaLink' in graph_data:
                self.logger.debug("MessageLabs: phishing Writing deltaLink(break) to the tracker file...")
                next_link = graph_data["@odata.deltaLink"]
            else:
                raise

            return emails, next_link

        except Exception as e:
            self.logger.error('Failed to process emails and links', __name__, exc_info=True)
            raise
