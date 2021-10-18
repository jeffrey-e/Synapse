#!/usr/bin/env python3
# -*- coding: utf8 -*-

# QRadar API requirements
from urllib.parse import quote
import ssl
import sys
import base64
import requests
import logging

# QRadar API from https://github.com/ibm-security-intelligence/api-samples
# This is a simple HTTP client that can be used to access the REST API
class RestApiClient:

    # Constructor for the RestApiClient Class
    def __init__(self, server_ip, auth_token, certificate_file, certificate_verification, version, **kwargs):
        self.logger = logging.getLogger(__name__)

        self.headers = {}
        self.headers['SEC'] = str(auth_token)
        self.server_ip = str(server_ip)
        self.headers['Version'] = str(version)
        self.base_uri = '/api/'
        # Create proxy config when proxy is provided
        self.http_proxy = kwargs.get('http_proxy', None)
        self.https_proxy = kwargs.get('https_proxy', None)

        if certificate_verification == "enabled":
            self.certs = certificate_file
        else:
            self.certs = False

    # This method is used to set up an HTTP request and send it to the server
    def call_api(self, endpoint, method, headers=None, params=[], data=None,
                 print_request=False):

        # If the caller specified customer headers merge them with the default
        # headers.
        actual_headers = self.headers.copy()
        if headers is not None:
            for header_key in headers:
                actual_headers[header_key] = headers[header_key]
        merged_headers = actual_headers

        path = self.parse_path(endpoint, params)

        url = 'https://' + self.server_ip + self.base_uri + path

        proxies = {
            'http': self.http_proxy,
            'https': self.https_proxy
        }

        self.logger.debug("Received the following request to perform: {}".format(url))
        if data:
            self.logger.debug("Received the following request body: {}".format(data))

        try:
            response = requests.request(method, url, headers=merged_headers, json=data, proxies=proxies, verify=self.certs, timeout=60)
            if (response.status_code in [200, 201]):
                self.logger.debug("the following response was received: {}".format(response.json()))
                return response
            elif response.status_code == 401:
                raise ConnectionRefusedError(response.content)
            # Retrieve alert information. Added a workaround to fix the delay in alert entity retrieval that causes a not found error sometimes
            elif response.status_code == 404:
                raise ValueError(response.content)
            else:
                raise QRadarUnhandledReturnCode
        except ValueError as e:
            self.logger.error('QRadar returned http {} with the following body: {}'.format(response.status_code, e))
            raise QRadarError
        except ConnectionRefusedError as e:
            self.logger.error("QRadar request failed with code 401: {}".format(e))
            raise QRadarError
        except Exception as e:
            self.logger.error("Could not retrieve data from QRadar: {}".format(e), exc_info=True)
            raise QRadarError

    # This method constructs the query string
    def parse_path(self, endpoint, params):

        path = endpoint + '?'

        if isinstance(params, list):

            for kv in params:
                if kv[1]:
                    path += kv[0]+'='+quote(kv[1])+'&'

        else:
            for k, v in params.items():
                if params[k]:
                    path += k+'='+quote(v)+'&'

        # removes last '&' or hanging '?' if no params.
        return path[:len(path)-1]

    # Simple getters that can be used to inspect the state of this client.
    def get_headers(self):
        return self.headers.copy()

    def get_server_ip(self):
        return self.server_ip

    def get_base_uri(self):
        return self.base_uri

### Error Handling classes

class QRadarError(Exception):
    """Raised when there is generic error with QRadar"""
    pass
class QRadarUnhandledReturnCode(Exception):
    """Raised when there is an unexpected return code with QRadar"""
    pass