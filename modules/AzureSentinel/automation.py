import json
import requests
import time
import logging
from datetime import date

from modules.TheHive.connector import TheHiveConnector
from modules.Cortex.connector import CortexConnector
from modules.AzureSentinel.connector import AzureSentinelConnector

# Load required object models
from thehive4py.models import Case, CustomFieldHelper, CaseObservable, CaseTask

logger = logging.getLogger(__name__)

current_time = 0

# When no condition is match, the default action is None
report_action = 'None'

class Automation():

    def __init__(self, webhook, cfg):
        logger.info('Initiating AzureSentinel Automation')
        self.TheHiveConnector = TheHiveConnector(cfg)
        self.AzureSentinelConnector = AzureSentinelConnector(cfg)
        self.webhook = webhook
        self.cfg = cfg
        self.report_action = report_action

    def parse_hooks(self):
        # Update incident status to active when imported as Alert
        if self.webhook.isAzureSentinelAlertImported():
            self.incidentId = self.webhook.data['object']['sourceRef']
            logger.info('Incident {} needs to be updated to status Active'.format(self.incidentId))
            self.AzureSentinelConnector.updateIncidentStatusToActive(self.incidentId)
            self.report_action = 'updateIncident'

        # Close incidents in Azure Sentinel
        if self.webhook.isClosedAzureSentinelCase() or self.webhook.isDeletedAzureSentinelCase() or self.webhook.isAzureSentinelAlertMarkedAsRead():
            if self.webhook.data['operation'] == 'Delete':
                self.case_id = self.webhook.data['objectId']
                self.classification = "Undetermined"
                self.classification_comment = "Closed by Synapse with summary: Deleted within The Hive"

            elif self.webhook.isAzureSentinelAlertMarkedAsRead():
                self.classification = "Undetermined"
                self.classification_comment = "Closed by Synapse with summary: Marked as Read within The Hive"
            else:
                self.case_id = self.webhook.data['object']['id']

                # Translation table for case statusses
                self.closure_status = {
                    "Indeterminate": "Undetermined",
                    "FalsePositive": "FalsePositive",
                    "TruePositive": "TruePositive",
                    "Other": "BenignPositive"
                }
                self.classification = self.closure_status[self.webhook.data['details']['resolutionStatus']]
                self.classification_comment = "Closed by Synapse with summary: {}".format(self.webhook.data['details']['summary'])

            logger.info('Incident {} needs to be be marked as Closed'.format(self.case_id))
            self.AzureSentinelConnector.closeIncident(self.webhook.incidentId, self.classification, self.classification_comment)
            self.report_action = 'closeIncident'

        return self.report_action
