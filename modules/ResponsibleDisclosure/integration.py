#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os
import sys
import logging
import json
import time
import hashlib
import re

from datetime import datetime
from core.integration import Main
from modules.ResponsibleDisclosure.connector import RDConnector
from modules.TheHive.connector import TheHiveConnector
from thehive4py.models import AlertArtifact, Case, Alert
from thehive4py.api import TheHiveApi

class Integration(Main):

    def __init__(self):
        super().__init__()
        self.RDConnector = RDConnector(self.cfg)
        self.TheHiveConnector = TheHiveConnector(self.cfg)

    def validateRequest(self, request):
        workflowReport = self.connectRD()
        if workflowReport['success']:
            return json.dumps(workflowReport), 200
        else:
            return json.dumps(workflowReport), 500

    def connectRD(self):
        self.logger.info('%s.connectResponsibleDisclosure starts', __name__)

        report = dict()
        report['success'] = bool()

        # Setup Tags
        self.tags = ['Responsible disclosure', 'Synapse']

        tracker_file = "./modules/ResponsibleDisclosure/email_tracker"
        link_to_load = ""
        if os.path.exists(tracker_file):
            self.logger.debug("Reading from the tracker file...")
            with open(tracker_file, "r") as tracker:
                link_to_load = tracker.read()

        if not link_to_load:
            link_to_load = self.cfg.get('ResponsibleDisclosure', 'list_endpoint')

        emails, new_link = self.RDConnector.scan(link_to_load)

        try:
            for email in emails:
                try:
                    if ('@removed' in email) or [email["from"]["emailAddress"]["address"]] in self.cfg.get('ResponsibleDisclosure', 'excluded_senders'):
                        continue
                    self.logger.debug("Found unread E-mail with id: {}".format(email['id']))

                    # Get the conversation id from the email
                    CID = email["conversationId"]
                    # Conversation id hash will be used as a unique identifier for the alert
                    CIDHash = hashlib.md5(CID.encode()).hexdigest()

                    email_date = datetime.strptime(email["receivedDateTime"], "%Y-%m-%dT%H:%M:%SZ")
                    epoch_email_date = email_date.timestamp() * 1000

                    alertTitle = "Responsible Disclosure - {}".format(email["subject"])

                    alertDescription = self.createDescription(email)

                    # Moving the email from Inbox to the new folder defined by variable to_move_folder in synapse.conf
                    # Disabled temporarily
                    # self.RDConnector.moveToFolder(self.cfg.get('ResponsibleDisclosure', 'email_address'), email['id'], self.cfg.get('ResponsibleDisclosure', 'to_move_folder'))

                    # Get all the attachments and upload to the hive observables
                    attachment_data = self.RDConnector.listAttachment(self.cfg.get('ResponsibleDisclosure', 'email_address'), email['id'])

                    all_artifacts = []
                    all_attachments = []

                    if attachment_data:
                        for att in attachment_data:
                            file_name = self.RDConnector.downloadAttachments(att['name'], att['attachment_id'], att['isInline'], att['contentType'])
                            all_attachments.append(file_name)

                            self.af = AlertArtifact(dataType='file', data=file_name, tlp=2, tags=['Responsible disclosure', 'Synapse'], ioc=True)

                            all_artifacts.append(self.af)

                    # Create the alert in thehive
                    alert = self.TheHiveConnector.craftAlert(
                        alertTitle,
                        alertDescription,
                        1,
                        epoch_email_date,
                        self.tags, 2,
                        "New",
                        "internal",
                        "ResponsibleDisclosure",
                        CIDHash,
                        all_artifacts,
                        self.cfg.get('ResponsibleDisclosure', 'case_template'))

                    # Check if the alert was created successfully
                    query = dict()
                    query['sourceRef'] = str(CIDHash)

                    # Look up if any existing alert in theHive
                    alert_results = self.TheHiveConnector.findAlert(query)

                    # If no alerts are found for corresponding CIDHASH, create a new alert
                    if len(alert_results) == 0:
                        createdAlert = self.TheHiveConnector.createAlert(alert)

                        # automatish antwoord to the original email sender from the responsible disclosure emailaddress
                        autoreply_subject_name = "RE: {}".format(email["subject"])

                        self.RDConnector.sendAutoReply("responsible.disclosure@nonexistent.company", email["from"]["emailAddress"]["address"], self.cfg.get('ResponsibleDisclosure', 'email_body_filepath'), autoreply_subject_name)

                    # If alert is found update the alert or it may have been migrated to case so update the case
                    if len(alert_results) > 0:
                        alert_found = alert_results[0]

                        # Check if alert is promoted to a case
                        if 'case' in alert_found:

                            case_found = self.TheHiveConnector.getCase(alert_found['case'])

                            # Create a case model
                            self.updated_case = Case

                            # Update the case with new description
                            # What if the email body is empty for new email, then use the old description
                            self.updated_case.description = case_found['description'] + "\n\n" + alertDescription

                            self.updated_case.id = alert_found['case']
                            self.TheHiveConnector.updateCase(self.updated_case, ["description"])
                            self.logger.info("updated the description of the case with id: {}".format(alert_found['case']))

                            # Check if there new observables available
                            if all_attachments:
                                for att in all_attachments:
                                    try:
                                        self.TheHiveConnector.addFileObservable(alert_found['case'], att, "email attachment")
                                    except Exception as e:
                                        self.logger.error(f"Encountered an error while creating a new file based observable: {e}", exc_info=True)
                                        continue
                        # Else it means there is no corresponding case so update the alert
                        else:
                            # create an alert model
                            self.updated_alert = Alert

                            # Update the alert with new description
                            # What if the email body is empty for new email, then use the old description
                            self.updated_alert.description = alert_found['description'] + "\n\n" + alertDescription

                            self.TheHiveConnector.updateAlert(alert_found['id'], self.updated_alert, ["description"])
                            self.logger.info("updated the description of the alert with id: {}".format(alert_found['id']))
                except Exception as e:
                    self.logger.error(e, exc_info=True)
                    continue

                if all_attachments:
                    for att in all_attachments:
                        os.remove(att)

            # Write the delta link to the tracker
            with open(tracker_file, "w+") as tracker:
                tracker.write(new_link)

            report['success'] = True
            return report

        except Exception as e:
            self.logger.error(e)
            self.logger.error('Connection failure', exc_info=True)
            report['success'] = False
            return report

    def createDescription(self, email):

        email_body = email['body']['content']
        subject = email["subject"]
        # Get the conversation id from the email
        CID = email["conversationId"]
        # Conversation id hash will be used as a unique identifier for the alert
        CIDHash = hashlib.md5(CID.encode()).hexdigest()

        # Parse all the URLs and add them to a field in the description table
        urls_list = re.findall(r'\<(https?://[\S]+?)\>', email_body)
        # "&#13;" is ascii for next line
        urls_str = ' &#13; '.join(str(x) for x in urls_list)

        from_e = email["from"]["emailAddress"]["address"]
        to_e = "N/A"
        if email["toRecipients"]:
            to_e = email["toRecipients"][0]["emailAddress"]["address"]

        OriginatingIP = "N/A"
        for header in email['internetMessageHeaders']:
            if header['name'] == 'X-Originating-IP':
                # Formatting the ip value, bydefault it comesup like [x.x.x.x]
                OriginatingIP = (header['value'][1:-1])

        # putting together the markdown table
        temp_fullbody = []
        temp_fullbody.append("|     |     |")
        temp_fullbody.append("|:-----|:-----|")
        temp_fullbody.append("|  " + "**" + "Subject" + "**" + "  |  " + subject + "  |")
        temp_fullbody.append("|  " + "**" + "Sender" + "**" + "  |  " + from_e + "  |")
        temp_fullbody.append("|  " + "**" + "Recipient" + "**" + "  |  " + to_e + "  |")
        temp_fullbody.append("|  " + "**" + "Originating IP" + "**" + "  |  " + OriginatingIP + "  |")
        temp_fullbody.append("|  " + "**" + "Received at" + "**" + "  |  " + email["receivedDateTime"] + "  |")
        temp_fullbody.append("|  " + "**" + "URL(s) in email" + "**" + "  |  " + urls_str + "  |")
        temp_fullbody.append("|  " + "**" + "Msg ID" + "**" + "  |  " + email['id'] + "  |")
        temp_fullbody.append("**" + "Email body" + "**")
        temp_fullbody.append("```")
        temp_fullbody.append(email_body)
        temp_fullbody.append("```")

        alertDescription = '\r\n'.join(str(x) for x in temp_fullbody)
        return alertDescription
