import json
import logging
import itertools
import os
import sys
import time
from thehive4py.query import In

from modules.Lexsi.connector import LexsiConnector
from modules.TheHive.connector import TheHiveConnector

from core.integration import Main


# Get logger
logger = logging.getLogger(__name__)

class Integration(Main):

    def __init__(self):
        super().__init__()
        self.lexsi = LexsiConnector(self.cfg)
        self.TheHiveConnector = TheHiveConnector(self.cfg)

    def validateRequest(self, request):

        if request.is_json:
            content = request.get_json()
            if 'type' in content and content['type'] == "Active":
                workflowReport = self.allIncidents2Alert(content['type'])
                if workflowReport['success']:
                    return json.dumps(workflowReport), 200
                else:
                    return json.dumps(workflowReport), 500
            else:
                self.logger.error('Missing type or type is not supported')
                return json.dumps({'sucess': False, 'message': "Missing type or type is not supported"}), 500
        else:
            self.logger.error('Not json request')
            return json.dumps({'sucess': False, 'message': "Request didn't contain valid JSON"}), 400

    def allIncidents2Alert(self, status):
        """
        Get all opened incidents created within lexsi
        and create alerts for them in TheHive
        """
        self.logger.info('%s.allincident2Alert starts', __name__)

        incidentsList = self.lexsi.getOpenItems()['result']

        report = dict()
        report['success'] = True
        report['incidents'] = list()

        try:
            # each incidents in the list is represented as a dict
            # we enrich this dict with additional details
            for incident in incidentsList:

                # Prepare new alert
                incident_report = dict()
                self.logger.debug("incident: %s" % incident)

                theHiveAlert = self.IncidentToHiveAlert(incident)

                # searching if the incident has already been converted to alert
                query = dict()
                query['sourceRef'] = str(incident['incident'])
                self.logger.info('Looking for incident %s in TheHive alerts', str(incident['incident']))
                results = self.TheHiveConnector.findAlert(query)
                if len(results) == 0:
                    self.logger.info('incident %s not found in TheHive alerts, creating it', str(incident['incident']))
                    try:

                        theHiveEsAlertId = self.TheHiveConnector.createAlert(theHiveAlert)['id']
                        self.TheHiveConnector.promoteAlertToCase(theHiveEsAlertId)

                        incident_report['raised_alert_id'] = theHiveEsAlertId
                        incident_report['lexsi_incident_id'] = incident['incident']
                        incident_report['success'] = True

                    except Exception as e:
                        self.logger.error(incident_report)
                        self.logger.error('%s.allincident2Alert failed', __name__, exc_info=True)
                        incident_report['success'] = False
                        if isinstance(e, ValueError):
                            errorMessage = json.loads(str(e))['message']
                            incident_report['message'] = errorMessage
                        else:
                            incident_report['message'] = str(e) + ": Couldn't raise alert in TheHive"
                        incident_report['incident_id'] = incident['incident']
                        # Set overall success if any fails
                        report['success'] = False

                else:
                    self.logger.info('incident %s already imported as alert, checking for updates', str(incident['incident']))
                    alert_found = results[0]

                    if self.TheHiveConnector.checkForUpdates(theHiveAlert, alert_found, str(incident['incident'])):
                        # Mark the alert as read
                        self.TheHiveConnector.markAlertAsRead(alert_found['id'])
                        incident_report['updated_alert_id'] = alert_found['id']
                        incident_report['sentinel_incident_id'] = str(incident['incident'])
                        incident_report['success'] = True
                    else:
                        incident_report['sentinel_incident_id'] = str(incident['incident'])
                        incident_report['success'] = True
                report['incidents'].append(incident_report)

            thehiveAlerts, open_lexsi_cases = self.lexsi_opened_alerts_thehive()
            self.set_alert_status_ignored(incidentsList, thehiveAlerts, open_lexsi_cases)

        except Exception as e:

            self.logger.error('Failed to create alert from Lexsi incident (retrieving incidents failed)', exc_info=True)
            report['success'] = False
            report['message'] = "%s: Failed to create alert from incident" % str(e)

        return report

    def IncidentToHiveAlert(self, incident):

        #
        # Creating the alert
        #

        # Setup Tags
        tags = ['Lexsi', 'incident', 'Synapse']

        # Skip for now
        artifacts = []

        # Retrieve the configured case_template
        CaseTemplate = self.cfg.get('Lexsi', 'case_template')

        # Build TheHive alert
        alert = self.TheHiveConnector.craftAlert(
            "{}: {}".format(incident['incident'], incident['title']),
            self.craftAlertDescription(incident),
            self.getHiveSeverity(incident),
            self.timestamp_to_epoch(incident['detected'], "%Y-%m-%d %H:%M:%S"),
            tags,
            2,
            'New',
            'internal',
            'Lexsi',
            str(incident['incident']),
            artifacts,
            CaseTemplate)

        return alert

    def craftAlertDescription(self, incident):
        """
            From the incident metadata, crafts a nice description in markdown
            for TheHive
        """
        self.logger.debug('craftAlertDescription starts')

        # Start empty
        description = ""

        # Add incident details table
        description += (
            '#### Summary\n\n' +
            '|                         |               |\n' +
            '| ----------------------- | ------------- |\n' +
            '| **URL**          | ' + "{}{}{}".format("```", str(incident['url']), "```") + ' |\n' +
            '| **Type**          | ' + str(incident['type']) + ' |\n' +
            '| **Severity**          | ' + str(incident['severity']) + ' |\n' +
            '| **Category**         | ' + str(incident['category']) + ' |\n' +
            '| **Updated**        | ' + str(incident['updated']) + ' |\n' +
            '| **Detected**        | ' + str(incident['detected']) + ' |\n' +
            '| **Source**        | ' + str(incident['source']) + ' |\n' +
            '| **Analyst Name(Lexsi)**        | ' + str(incident['analystName']) + ' |\n' +
            '| **Link to Orange Portal**        | ' + str("https://portal.cert.orangecyberdefense.com/cybercrime/{}".format(incident['id'])) + ' |\n' +
            '\n\n\n\n')

        return description

    def timestamp_to_epoch(self, date_time, pattern):
        return int(time.mktime(time.strptime(date_time, pattern))) * 1000

    def getHiveSeverity(self, incident):
        # severity in TheHive is either low, medium, high or critical
        # while severity in Lexsi is from 0 to 5
        if int(incident['severity']) in {0, 5}:
            return 1
        # elif int(incident['severity']) in {2,3}:
        #    return 2
        # elif int(incident['severity']) in {4,5}:
        #    return 3
        else:
            return 2

    def lexsi_opened_alerts_thehive(self):
        thehiveAlerts = []
        open_lexsi_cases = {}
        query = In('tags', ['Lexsi'])

        self.logger.info('Looking for incident in TheHive alerts with tag Lexsi')
        # self.logger.info(query)
        results = self.TheHiveConnector.findAlert(query)
        for alert_found in results:
            # Check if a case is linked
            if 'case' in alert_found:
                try:
                    case_found = self.TheHiveConnector.getCase(alert_found['case'])
                    # Check if the status is open. Only then append it to the list
                    if case_found['status'] == "Open":
                        open_lexsi_cases[alert_found['sourceRef']] = case_found
                        thehiveAlerts.append(alert_found['sourceRef'])
                except Exception as e:
                    self.logger.error("Could not find case: {}".format(e), exc_info=True)
                    continue
        self.logger.debug("Lexsi Alerts opened in theHive: {}".format(thehiveAlerts))
        return thehiveAlerts, open_lexsi_cases

    def compare_lists(self, list1, list2):
        return list(set(list1) - set(list2))

    def set_alert_status_ignored(self, incidentsList, thehiveAlerts, open_lexsi_cases):
        lexsi_reporting = []
        # incidentsList = self.lexsi.getOpenItems()['result']

        for incident in incidentsList:
            lexsi_reporting.append(incident['incident'])

        self.logger.debug("the list of opened Lexsi Incidents: {}".format(lexsi_reporting))
        uncommon_elements = self.compare_lists(thehiveAlerts, lexsi_reporting)
        # uncommon_elements=['476121']
        self.logger.debug("Open cases present in TheHive but not in list of opened Lexsi Incidents: {}".format((uncommon_elements)))

        for element in uncommon_elements:
            self.logger.info("Preparing to close the case for {}".format(element))
            query = dict()
            query['sourceRef'] = str(element)
            self.logger.debug('Looking for incident %s in TheHive alerts', str(element))
            try:
                if element in open_lexsi_cases:
                    # Resolve the case
                    case_id = open_lexsi_cases[element]['id']
                    self.logger.debug("Case id for element {}: {}".format(element, case_id))
                    self.logger.debug("Preparing to resolve the case")
                    self.TheHiveConnector.closeCase(case_id)
                    self.logger.debug("Closed case with id {} for {}".format(case_id, element))

            except Exception as e:
                self.logger.error("Could not close case: {}".format(e), exc_info=True)
                continue
