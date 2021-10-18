import re
import json
import requests
import time
import logging
from datetime import date

from modules.TheHive.connector import TheHiveConnector
from modules.Cortex.connector import CortexConnector
from modules.ResponsibleDisclosure.connector import RDConnector

logger = logging.getLogger(__name__)

# When no condition is match, the default action is None
report_action = 'None'

class Automation():

    def __init__(self, webhook, cfg):
        self.logger = logger
        self.logger.info('Initiating RD Automation')
        self.TheHiveConnector = TheHiveConnector(cfg)
        self.webhook = webhook
        self.cfg = cfg
        self.report_action = report_action
        self.RDConnector = RDConnector(cfg)

    def parse_hooks(self):
        self.logger.info(f'{__name__}.parse_hooks starts')
        # Only continue if the right webhook is triggered
        
        if self.webhook.isResponsibleDisclosureAlertImported():
            pass
        else:
            return False
        try:
            # Define variables and actions based on certain webhook types
            self.case_id = self.webhook.data['object']['case']
          
            #parse Mgs ID field from the webhook

            self.email_id = re.search(r"Msg ID[\s\S]+?\|\s+(\S+)\s+\|", str(self.webhook.data['object']))
            self.logger.debug(f"regex match {self.email_id.group(1)}")

            #get all the attachments and upload to the hive observables
            attachment_data= self.RDConnector.listAttachment(self.cfg.get('ResponsibleDisclosure', 'email_address'), self.email_id.group(1))
            
            all_attachments = []

            if attachment_data:
                for att in attachment_data:
                    try:
                        file_name = self.RDConnector.downloadAttachments(att['name'], att['attachment_id'], att['isInline'], att['contentType'] )
                        all_attachments.append(file_name)
                        self.TheHiveConnector.addFileObservable(self.case_id, file_name, "email attachment")
                        self.logger.info(f"Observable: {file_name} has been updated to Case: {self.case_id}")

                    except Exception as e:
                        self.logger.error(e, exc_info=True)
                        continue
                    finally:
                        os.remove(file_name)
                        self.logger.debug(f"File: {file_name} has been removed")

            return True
        except Exception as e:
            self.logger.error(e, exc_info=True)
            return False
        