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
        logger.debug(f'Azure Sentinel webhook parsing starts')
        # Update incident status to active when imported as Alert
        if self.webhook.isAzureSentinelAlertImported():
            # We need to get the alert sourceRefs from the opened case for TH4
            if self.webhook.data['objectType'] == "case":
                alert_query = {'case': self.webhook.data['objectId']}
                alerts = self.TheHiveConnector.findAlert(alert_query)
                for alert in alerts:
                    if 'sourceRef' in alert and alert['source'] == 'Azure_Sentinel_incidents':
                        logger.info(f"Sentinel incident '{alert['title']}' needs to be updated to status Active")
                        self.AzureSentinelConnector.updateIncidentStatusToActive(alert['sourceRef'])
            else:
                self.incidentId = self.webhook.data['object']['sourceRef']
                logger.info(f'Incident {self.incidentId} needs to be updated to status Active')
                self.AzureSentinelConnector.updateIncidentStatusToActive(self.incidentId)
                self.report_action = 'updateIncident'

        # Close incidents in Azure Sentinel
        if self.webhook.isClosedAzureSentinelCase() or self.webhook.isDeletedAzureSentinelCase() or self.webhook.isAzureSentinelAlertMarkedAsRead():
            if self.webhook.data['operation'].lower() == 'delete':
                logger.debug(f'Azure Sentinel: Adding Delete comment')
                self.case_id = self.webhook.data['objectId']
                self.classification = "Undetermined"
                self.classification_comment = "Closed by Synapse with summary: Deleted within The Hive"

            elif self.webhook.isAzureSentinelAlertMarkedAsRead():
                logger.debug(f'Azure Sentinel: Adding Undetermined comment')
                self.case_id = self.webhook.data['objectId']
                self.classification = "Undetermined"
                self.classification_comment = "Closed by Synapse with summary: Marked as Read within The Hive"
            else:
                logger.debug(f'Azure Sentinel: Adding Case Closure comment')
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
            alert_query = {'case': self.webhook.data['objectId']}
            alerts = self.TheHiveConnector.findAlert(alert_query)
            for alert in alerts:
                if 'sourceRef' in alert and alert['source'] == 'Azure_Sentinel_incidents':
                    logger.info(f"Closing Sentinel incident {alert['title']}")
                    self.AzureSentinelConnector.closeIncident(alert['sourceRef'], self.classification, self.classification_comment)
            self.report_action = 'closeIncident'

        return self.report_action
