#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os
import sys
import logging
import json
import time

from datetime import datetime
from core.integration import Main
from modules.MessageLabs.connector import MLabsConnector
from modules.TheHive.connector import TheHiveConnector

class Integration(Main):

    def __init__(self):
        super().__init__()
        self.mlabsConnector = MLabsConnector(self.cfg)
        self.theHiveConnector = TheHiveConnector(self.cfg)

    def validateRequest(self, request):
        workflowReport = self.connectMLabs()
        if workflowReport['success']:
            return json.dumps(workflowReport), 200
        else:
            return json.dumps(workflowReport), 500

    def connectMLabs(self):
        self.logger.info('%s.connectMLabs starts', __name__)

        report = dict()
        report['success'] = bool()

        # Setup Tags
        self.tags = ['MessageLabs', 'Synapse']

        try:
            tracker_file = "./modules/MessageLabs/phishing_tracker"
            link_to_load = ""
            if os.path.exists(tracker_file):
                self.logger.debug("MessageLabs: phishing Reading from the tracker file...")
                with open(tracker_file, "r") as tracker:
                    link_to_load = tracker.read()

            if not link_to_load:
                link_to_load = self.cfg.get('MessageLabs', 'list_endpoint')

            unread, new_link = self.mlabsConnector.scan(link_to_load)

            for msg in unread:
                if msg['subject'] != self.cfg.get('MessageLabs', 'subject_contains'):
                    continue

                fullBody = msg['body']['content']
                subject = ""
                internalMessageId = ""

                for line in fullBody.splitlines():
                    if line.startswith("Subject"):
                        subject = line
                    if line.startswith("Message ID:"):
                        internalMessageId = line.split(" ID: ")[-1]
                    if line.startswith("Date:"):
                        email_date = datetime.strptime(line.split("Date: ")[-1], "%a, %d %b %Y %H:%M:%S %z")
                        epoch_email_date = email_date.timestamp() * 1000

                caseTitle = str(self.cfg.get('MessageLabs', 'subject_contains') + " - " + str(subject))
                caseDescription = fullBody

                alert = self.theHiveConnector.craftAlert(caseTitle, caseDescription, 1, epoch_email_date, self.tags, 2, "New", "internal", "MessageLabs", internalMessageId, [], self.cfg.get('MessageLabs', 'case_template'))
                try:
                    createdCase = self.theHiveConnector.createAlert(alert)
                except ValueError as e:
                    self.logger.info("Alert with sourceRef '{}' already exists".format(internalMessageId))

            with open(tracker_file, "w+") as tracker:
                tracker.write(new_link)

            report['success'] = True
            return report

        except Exception as e:
            self.logger.error('Connection failure', exc_info=True)
            report['success'] = False
            return report
