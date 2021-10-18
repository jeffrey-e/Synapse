import json
import requests
import time
import logging
from datetime import date

from modules.TheHive.connector import TheHiveConnector
from modules.Cortex.connector import CortexConnector
from modules.QRadar.connector import QRadarConnector

# Load required object models
from thehive4py.models import Case, CustomFieldHelper, CaseObservable, CaseTask

logger = logging.getLogger(__name__)

# When no condition is match, the default action is None
report_action = 'None'

class Automation():

    def __init__(self, webhook, cfg):
        logger.info('Initiating QRadarAutomation')
        self.TheHiveConnector = TheHiveConnector(cfg)
        self.QRadarConnector = QRadarConnector(cfg)
        self.webhook = webhook
        self.cfg = cfg
        self.report_action = report_action

    def checkIfInClosedCaseOrAlertMarkedAsRead(self, sourceref):
        query = dict()
        query['sourceRef'] = str(sourceref)
        logger.debug('Checking if third party ticket({}) is linked to a closed case'.format(sourceref))
        alert_results = self.TheHiveConnector.findAlert(query)
        if len(alert_results) > 0:
            alert_found = alert_results[0]
            if alert_found['status'] == 'Ignored':
                logger.info(f"{sourceref} is found in alert {alert_found['id']} that has been marked as read")
                return {"resolutionStatus": "Indeterminate", "summary": "Closed by Synapse with summary: Marked as Read within The Hive"}
            elif 'case' in alert_found:
                # Check if alert is present in closed case
                case_found = self.TheHiveConnector.getCase(alert_found['case'])
                if case_found['status'] == "Resolved":
                    logger.info(f"{sourceref} was found in a closed case {case_found['id']}")
                    resolution_status = "N/A"
                    resolution_summary = "N/A"
                    # Return information required to sync with third party
                    if 'resolutionStatus' in case_found:
                        resolution_status = case_found['resolutionStatus']
                    if 'summary' in case_found:
                        resolution_summary = case_found['summary']
                    return {"resolutionStatus": resolution_status, "summary": resolution_summary}
        return False

    def parse_hooks(self):
        # Update incident status to active when imported as Alert
        if self.webhook.isQRadarAlertImported():
            self.offense_id = self.webhook.data['object']['sourceRef']

            # Check if the alert is imported in a closed case
            closure_info = self.checkIfInClosedCaseOrAlertMarkedAsRead(self.offense_id)
            if closure_info:
                logger.info('Qradar offense({}) is linked to a closed case'.format(self.offense_id))
                # Close incident and continue with the next incident
                self.QRadarConnector.closeOffense(self.offense_id)

        # Close offenses in QRadar
        if self.webhook.isClosedQRadarCase() or self.webhook.isDeletedQRadarCase() or self.webhook.isQRadarAlertMarkedAsRead():
            if self.webhook.data['operation'] == 'Delete':
                self.case_id = self.webhook.data['objectId']
                logger.info('Case {} has been deleted'.format(self.case_id))

            elif self.webhook.data['objectType'] == 'alert':
                self.alert_id = self.webhook.data['objectId']
                logger.info('Alert {} has been marked as read'.format(self.alert_id))
                self.QRadarConnector.closeOffense(self.webhook.data['object']['sourceRef'])

            else:
                self.case_id = self.webhook.data['object']['id']
                logger.info('Case {} has been marked as resolved'.format(self.case_id))

            if hasattr(self, 'case_id'):
                if hasattr(self.webhook, 'ext_alert_id'):
                    logger.info("Closing offense {} for case {}".format(self.webhook.ext_alert_id, self.case_id))
                    self.QRadarConnector.closeOffense(self.webhook.ext_alert_id)

                elif len(self.webhook.ext_alert_ids) > 0:
                    # Close offense for every linked offense
                    logger.info("Found multiple offenses {} for case {}".format(self.webhook.ext_alert_ids, self.case_id))
                    for offense_id in self.webhook.ext_alert_ids:
                        logger.info("Closing offense {} for case {}".format(offense_id, self.case_id))
                        self.QRadarConnector.closeOffense(offense_id)

            self.report_action = 'closeOffense'

        return self.report_action
