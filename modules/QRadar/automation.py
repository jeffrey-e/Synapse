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

current_time = 0

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

    def parse_hooks(self):
        # Close offenses in QRadar
        if self.webhook.isClosedQRadarCase() or self.webhook.isDeletedQRadarCase() or self.webhook.isQRadarAlertMarkedAsRead():
            if self.webhook.data['operation'] == 'Delete':
                self.case_id = self.webhook.data['objectId']
                logger.info('Case {} has been deleted'.format(self.case_id))

            elif self.webhook.data['objectType'] == 'alert':
                self.alert_id = self.webhook.data['objectId']
                logger.info('Alert {} has been marked as read'.format(self.alert_id))
                self.QRadarConnector.closeOffense(self.webhook.offenseId)

            else:
                self.case_id = self.webhook.data['object']['id']
                logger.info('Case {} has been marked as resolved'.format(self.case_id))

            if hasattr(self, 'case_id'):
                if hasattr(self.webhook, 'offenseId'):
                    logger.info("Closing offense {} for case {}".format(self.webhook.offenseId, self.case_id))
                    self.QRadarConnector.closeOffense(self.webhook.offenseId)

                elif len(self.webhook.offenseIds) > 0:
                    # Close offense for every linked offense
                    logger.info("Found multiple offenses {} for case {}".format(self.webhook.offenseIds, self.case_id))
                    for offenseId in self.webhook.offenseIds:
                        logger.info("Closing offense {} for case {}".format(offenseId, self.case_id))
                        self.QRadarConnector.closeOffense(offenseId)

            self.report_action = 'closeOffense'

        return self.report_action
