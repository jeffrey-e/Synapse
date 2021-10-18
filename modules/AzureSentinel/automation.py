import logging
from datetime import date

from modules.TheHive.connector import TheHiveConnector
from modules.Cortex.connector import CortexConnector
from modules.AzureSentinel.connector import AzureSentinelConnector

# Load required object models
from thehive4py.models import Case, CustomFieldHelper, CaseObservable, CaseTask

logger = logging.getLogger(__name__)

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
        self.closure_status = {
            "Indeterminate": "Undetermined",
            "FalsePositive": "FalsePositive",
            "TruePositive": "TruePositive",
            "Other": "BenignPositive"
        }

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
                    if 'resolutionStatus' in case_found and case_found['resolutionStatus'] == "Duplicated":
                        merged_case_found = self.getFinalMergedCase(case_found)
                        logger.debug(f"found merged cases {merged_case_found}")
                        if merged_case_found:
                            if merged_case_found['status'] != "Resolved":
                                return False
                            else:
                                case_found = merged_case_found
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
        if self.webhook.isAzureSentinelAlertImported():
            self.incidentId = self.webhook.data['object']['sourceRef']

            # Check if the alert is imported in a closed case
            closure_info = self.checkIfInClosedCaseOrAlertMarkedAsRead(self.incidentId)
            if closure_info:
                logger.info('Sentinel incident({}) is linked to a closed case'.format(self.incidentId))
                # Translation table for case statusses

                classification = self.closure_status[closure_info['resolutionStatus']]
                classification_comment = "Closed by Synapse with summary: {}".format(closure_info['summary'])
                # Close incident and continue with the next incident
                self.AzureSentinelConnector.closeIncident(self.incidentId, classification, classification_comment)

            else:
                logger.info('Incident {} needs to be updated to status Active'.format(self.incidentId))
                self.AzureSentinelConnector.updateIncidentStatusToActive(self.incidentId)
                self.report_action = 'updateIncident'

        # Close incidents in Azure Sentinel
        if self.webhook.isClosedAzureSentinelCase() or self.webhook.isDeletedAzureSentinelCase() or self.webhook.isAzureSentinelAlertMarkedAsRead():
            if self.webhook.data['operation'] == 'Delete':
                self.case_id = self.webhook.data['objectId']
                self.classification = "Undetermined"
                self.classification_comment = "Closed by Synapse with summary: Deleted within The Hive"
                logger.info('Case {} has been deleted'.format(self.case_id))

            elif self.webhook.data['objectType'] == 'alert':
                self.alert_id = self.webhook.data['objectId']
                self.incidentId = self.webhook.data['object']['sourceRef']
                self.classification = "Undetermined"
                self.classification_comment = "Closed by Synapse with summary: Marked as Read within The Hive"
                logger.info('Alert {} has been marked as read'.format(self.webhook.data['object']['sourceRef']))
                self.AzureSentinelConnector.closeIncident(self.incidentId, self.classification, self.classification_comment)

            # Ensure duplicated incidents don't get closed when merged, but only when merged case is closed
            elif 'resolutionStatus' in self.webhook.data['details'] and self.webhook.data['details']['resolutionStatus'] != "Duplicated":
                self.case_id = self.webhook.data['object']['id']
                self.classification = self.closure_status[self.webhook.data['details']['resolutionStatus']]
                self.classification_comment = "Closed by Synapse with summary: {}".format(self.webhook.data['details']['summary'])
                logger.info('Case {} has been marked as resolved'.format(self.case_id))

                if 'mergeFrom' in self.webhook.data['object']:
                    logger.info(f'Case {self.case_id} is a merged case. Finding original cases')
                    original_cases = []
                    for merged_case in self.webhook.data['object']['mergeFrom']:
                        original_cases.extend(self.getOriginalCases(merged_case))
                    # Find alerts for each original case
                    for original_case in original_cases:
                        query = {'case': original_case['id']}
                        found_alerts = self.TheHiveConnector.findAlert(query)
                        # Close alerts that have been found
                        for found_alert in found_alerts:
                            logger.info("Closing incident {} for case {}".format(found_alert['sourceRef'], self.case_id))
                            self.AzureSentinelConnector.closeIncident(found_alert['sourceRef'], self.classification, self.classification_comment)

            if hasattr(self, 'case_id'):
                if hasattr(self.webhook, 'ext_alert_id'):
                    logger.info("Closing incident {} for case {}".format(self.webhook.ext_alert_id, self.case_id))
                    self.AzureSentinelConnector.closeIncident(self.webhook.ext_alert_id, self.classification, self.classification_comment)

                elif len(self.webhook.ext_alert_ids) > 0:
                    # Close incident for every linked incident
                    logger.info("Found multiple incidents {} for case {}".format(self.webhook.ext_alert_ids, self.case_id))
                    for incident_id in self.webhook.ext_alert_ids:
                        logger.info("Closing incident {} for case {}".format(incident_id, self.case_id))
                        self.AzureSentinelConnector.closeIncident(incident_id, self.classification, self.classification_comment)

            self.report_action = 'closeIncident'

        return self.report_action

    def getOriginalCases(self, merged_from_case_id, handled_cases=[]):
        cases_found = []
        case_found = self.TheHiveConnector.getCase(merged_from_case_id)
        if 'mergeFrom' in case_found:
            if merged_from_case_id not in handled_cases:
                handled_cases.append(merged_from_case_id)
                for merged_case in self.webhook.data['object']['mergeFrom']:
                    cases_found.extend(self.getOriginalCases(merged_case, handled_cases))
        else:
            cases_found.append(case_found)
            return cases_found

    def getFinalMergedCase(self, duplicated_case, handled_cases=[]):
        if 'mergeInto' in duplicated_case:
            merged_into = duplicated_case['mergeInto']
            case_found = self.TheHiveConnector.getCase(merged_into)
            if 'resolutionStatus' in case_found:
                if case_found['resolutionStatus'] == "Duplicated" and merged_into not in handled_cases:
                    handled_cases.append(merged_into)
                    case_found = self.getFinalMergedCase(case_found, handled_cases)
        else:
            case_found = duplicated_case
        return case_found
