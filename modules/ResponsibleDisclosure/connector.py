#!/usr/bin/env python3
# -*- coding: utf8 -*-

import logging
import sys
import os
import json
import msal
import requests

class RDConnector:
    'ResponsibleDisclosure connector via Graph API'

    def __init__(self, cfg):
        self.logger = logging.getLogger('workflows.' + __name__)
        self.cfg = cfg
        self.proxy = self.cfg.get('ResponsibleDisclosure', 'proxy')
        self.proxies = {
            'http': self.proxy,
            'https': self.proxy
        }
        self.temp_filepath = self.cfg.get('ResponsibleDisclosure', 'temp_filepath')
        
        # Check If temp_filepath Directory Exists, If Not, Create It
        if not os.path.exists(self.temp_filepath):
            os.makedirs(self.temp_filepath)

        self.token = self.getToken()

    def getToken(self):
        self.logger.info('%s. getToken starts', __name__)
        try:

            authority = self.cfg.get('ResponsibleDisclosure', 'authority')
            client_id = self.cfg.get('ResponsibleDisclosure', 'client_id')
            scope = self.cfg.get('ResponsibleDisclosure', 'scope')
            secret = self.cfg.get('ResponsibleDisclosure', 'secret')

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
            self.logger.error("ResponsibleDisclosure: {}".format(result.get("error")), exc_info=True)
            self.logger.error("ResponsibleDisclosure: {}".format(result.get("error_description")), exc_info=True)
            self.logger.error("ResponsibleDisclosure: {}".format(result.get("correlation_id")), exc_info=True)
            raise

    def scan(self, link_to_load):

        self.logger.info('%s.scan starts', __name__)

        try:
            graph_data = requests.get(link_to_load, headers = {'Authorization': 'Bearer ' + self.token, 'Prefer': 'outlook.body-content-type=text'}, verify = False, proxies = self.proxies, timeout=60).json()
            emails = graph_data['value']
            next_link = ""
            if '@odata.nextLink' in graph_data:
                self.logger.debug("ResponsibleDisclosure: will write nextLink(loop) to the tracker file...")
                next_link = graph_data["@odata.nextLink"]
            elif '@odata.deltaLink' in graph_data:
                self.logger.debug("ResponsibleDisclosure: will write deltaLink(break) to the tracker file...")
                next_link = graph_data["@odata.deltaLink"]
            else:
                raise
            return emails, next_link

        except Exception as e:
            self.logger.error('Failed to process emails', __name__, exc_info=True)
            raise
    
    def sendAutoReply(self, from_email, to_email, template_file_name, subject_name):
        self.logger.info(f'{__name__}.sendAutoReply starts')
        #build the email response
        try:
            with open(template_file_name,'r') as f:
                template_body = f.read()
            
            self.send_email_endpoint = self.cfg.get('ResponsibleDisclosure', 'send_email_endpoint')
            
            payload = {
            "message": {
                
                "body": {
                "contentType": "html"
                },
                "toRecipients": [
                {
                    "emailAddress": {
                    }
                }
                ],
                "from": {
                "emailAddress": {
                }
                }
            },
                "saveToSentItems": "True"
            }


            payload["message"]["subject"] = subject_name
            payload["message"]["body"]["content"] = template_body
            payload["message"]["from"]["emailAddress"]["address"] = from_email
            payload["message"]["toRecipients"][0]["emailAddress"]["address"] = to_email

            jsonData=json.dumps(payload)
            
            #post the auto reply email body
            graph_data = requests.post(self.send_email_endpoint, headers={'Authorization': 'Bearer ' + self.token,'Content-Type': 'application/json'}, data=jsonData, verify=False, timeout=60)

            self.logger.info("Sent thankyou email to {} from {}\n".format(to_email,from_email))
        except Exception as e:
            self.logger.error('Failed to send thankyou email', __name__, exc_info=True)
            self.logger.error(e)
            raise
        
    def moveToFolder(self, email_address, id, folder_name):
        self.logger.info(f'{__name__}.moveToFolder starts')
        move_request_url = 'https://graph.microsoft.com/v1.0/users/{}/messages/{}/move'
        http_request = move_request_url.format(email_address, id)
        
        mailFolders_data = requests.get('https://graph.microsoft.com/v1.0/users/{}/mailFolders'.format(email_address), headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'}, verify=False, proxies=self.proxies, timeout=60).json()
        try:
            folderId = ''
            for folder in mailFolders_data['value']:
                if folder['displayName'] == folder_name:
                    folderId = folder['id']
            
            request = {"DestinationId": folderId}
            
            response = requests.post(http_request, headers={'Authorization': 'Bearer ' + self.token}, json=request, verify=False, proxies=self.proxies, timeout=60)

            self.logger.info('move response: {}'.format(response))
        except Exception as e:
            self.logger.error(f'{mailFolders_data} {e}')
            self.logger.error('Failed to move email: {}'.format(id), exc_info=True)

    def listAttachment(self, email_address, id):
        self.logger.info(f'{__name__}.listAttachment starts')
        self.email_address = email_address
        self.id = id
        list_attachment_url = f'https://graph.microsoft.com/v1.0/users/{self.email_address}/messages/{self.id}/attachments'

        attachments_list = []

        try:
            attachment_data = requests.get(list_attachment_url, headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'}, verify=False, proxies=self.proxies, timeout=60).json()
            for attachment in  attachment_data['value']:
                attachments_list.append({'name': attachment['name'], 'isInline': attachment['isInline'], 'contentType': attachment['contentType'], 'attachment_id': attachment['id']})
            return attachments_list
        except Exception as e:
            self.logger.error(e)
            self.logger.error('Failed to retrieve attachment list from email: {}'.format(id), exc_info=True)

    def downloadAttachments(self, attachment_name, attachment_id, isInline, attachment_content_type):
        self.logger.info(f'{__name__}.downloadAttachments starts')

        self.attachment_name = attachment_name
        self.attachment_id = attachment_id
        self.isInline = isInline
        self.attachment_content_type = attachment_content_type
        self.filepath = self.temp_filepath + self.attachment_name

        attachment_dwnld_url = f'https://graph.microsoft.com/v1.0/users/{self.email_address}/messages/{self.id}/attachments/{self.attachment_id}/$value'

        try:
            self.attachement_response = requests.get(attachment_dwnld_url, headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'}, verify=False, proxies=self.proxies, timeout=60)
                        
            file_name= self.writeFile()
            return file_name

        except Exception as e:
            self.logger.error(e)
            self.logger.error('Failed to download file: {}'.format(id), exc_info=True)

    def writeFile(self):
        self.logger.info(f'{__name__}.writeFile starts')

        with open(self.filepath, 'wb') as out:
            out.write(self.attachement_response.content)
        return self.filepath
