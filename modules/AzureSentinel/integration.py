import json
from core.integration import Main
from modules.AzureSentinel.connector import AzureSentinelConnector
from modules.TheHive.connector import TheHiveConnector

class Integration(Main):

    def __init__(self):
        super().__init__()
        self.azureSentinelConnector = AzureSentinelConnector(self.cfg)
        self.TheHiveConnector = TheHiveConnector(self.cfg)

    def craftAlertDescription(self, incident):
        """
            From the incident metadata, crafts a nice description in markdown
            for TheHive
        """
        self.logger.debug('craftAlertDescription starts')

        # Start empty
        description = ""

        # Add url to incident
        self.url = ('[Sentinel: %s](%s)' % (str(incident['properties']['incidentNumber']), str(incident['properties']['incidentUrl'])))
        description += '#### Incident \n - ' + self.url + '\n\n'
        if 'defender' in incident:
            self.defender_url = ('[Defender for Endpoint: %s](%s)' % (str(incident['defender']['id']), str(incident['defender']['url'])))
            description += '- ' + self.defender_url + '\n\n'

        # Format associated rules
        if len(incident['rules']) > 0:
            rule_names_formatted = "#### Rules triggered \n"
            unique_rule_set = set()
            for rule in incident['rules']:
                if 'properties' in rule:
                    self.logger.debug('Received the following rule information: {}'.format(rule))
                    rule_name = rule['properties']['displayName']
                    if rule_name not in unique_rule_set:
                        unique_rule_set.add(rule_name)
                        rule_names_formatted += "- %s \n" % (rule_name)
                    else:
                        continue
                else:
                    self.logger.warning('could not find properties in rule: {}'.format(rule))

            # Add rules overview to description
            description += rule_names_formatted + '\n\n'

        # Format associated alerts
        if len(incident['related_alerts']) > 0:
            alert_names_formatted = "#### Alerts triggered \n"
            unique_alert_set = set()
            for related_alert in incident['related_alerts']:
                if 'properties' in related_alert:
                    self.logger.debug('Received the following alert information: {}'.format(related_alert))
                    alert_name = related_alert['properties']['alertDisplayName']
                    if alert_name not in unique_alert_set:
                        unique_alert_set.add(alert_name)
                        alert_names_formatted += "- %s \n" % (alert_name)
                else:
                    self.logger.warning('could not find properties in alert: {}'.format(related_alert))

            # Add alerts overview to description
            description += alert_names_formatted + '\n\n'

        # Format associated documentation
        self.uc_links_formatted = "#### Use Case documentation: \n"
        kb_url = self.cfg.get('AzureSentinel', 'kb_url')
        if 'use_case_names' in incident and incident['use_case_names']:
            self.uc_links_formatted = "#### Use Case documentation \n"
            for uc in incident['use_case_names']:
                replaced_kb_url = kb_url.replace('<uc_kb_name>', uc)
                self.uc_links_formatted += f"- [{uc}]({replaced_kb_url}) \n"

            # Add associated documentation
            description += self.uc_links_formatted + '\n\n'

        # Add mitre Tactic information
        # https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

        # Table to translate names to identifiers for the url
        mitre_tactic_table = {
            "Reconnaissance": {"id": "TA0043", "name": "Reconnaissance"},
            "ResourceDevelopment": {"id": "TA0042", "name": "Resource Development"},
            "InitialAccess": {"id": "TA0001", "name": "Initial Access"},
            "Execution": {"id": "TA0002", "name": "Execution"},
            "Persistence": {"id": "TA0003", "name": "Persistence"},
            "PrivilegeEscalation": {"id": "TA0004", "name": "Privilege Escalation"},
            "DefenseEvasion": {"id": "TA0005", "name": "Defense Evasion"},
            "CredentialAccess": {"id": "TA0006", "name": "Credential Access"},
            "Discovery": {"id": "TA0007", "name": "Discovery"},
            "LateralMovement": {"id": "TA0008", "name": "Lateral Movement"},
            "Collection": {"id": "TA0009", "name": "Collection"},
            "CommandAndControl": {"id": "TA0011", "name": "Command and Control"},
            "Exfiltration": {"id": "TA0010", "name": "Exfiltration"},
            "Impact": {"id": "TA0040", "name": "Impact"}
        }

        # Check if the mitre ids need to be extracted
        if self.cfg.getboolean('AzureSentinel', 'extract_mitre_ids'):
            # Extract mitre tactics
            if len(incident['properties']['additionalData']['tactics']) > 0:
                incident['mitre_tactics'] = []
                for tactic in incident['properties']['additionalData']['tactics']:
                    if tactic in mitre_tactic_table:
                        incident['mitre_tactics'].append(mitre_tactic_table[tactic])
                        self.tags.append(mitre_tactic_table[tactic]['id'])
                    else:
                        incident['mitre_tactics'].append({"id": None, "name": tactic})

        mitre_ta_links_formatted = "#### MITRE Tactics \n"
        if 'mitre_tactics' in incident:
            for tactic in incident['mitre_tactics']:
                if tactic['id']:
                    mitre_ta_links_formatted += "- [%s](%s/%s) \n" % (tactic['name'], 'https://attack.mitre.org/tactics/', tactic['id'])
                else:
                    mitre_ta_links_formatted += "- %s \n" % (tactic['name'])

            # Add associated documentation
            description += mitre_ta_links_formatted + '\n\n'

        # #Add mitre Technique information
        # mitre_t_links_formatted = "#### MITRE Techniques \n"
        # if 'mitre_techniques' in incident and incident['mitre_techniques']:
        #     for technique in incident['mitre_techniques']:
        #         mitre_t_links_formatted += "- [%s](%s/%s) \n" % (technique, 'https://attack.mitre.org/techniques/', technique)

        # Add a custom description when the incident does not contain any
        if 'description' not in incident['properties']:
            incident['properties']['description'] = "N/A"

        # Add incident details table
        description += (
            '#### Summary\n\n' +
            '|                         |               |\n' +
            '| ----------------------- | ------------- |\n' +
            '| **Start Time**          | ' + str(self.azureSentinelConnector.formatDate("description", incident['properties']['createdTimeUtc'])) + ' |\n' +
            '| **incident ID**          | ' + str(incident['properties']['incidentNumber']) + ' |\n' +
            '| **Description**         | ' + str(incident['properties']['description'].replace('\n', '')) + ' |\n' +
            '| **incident Type**        | ' + str(incident['type']) + ' |\n' +
            '| **incident Source**      | ' + str(incident['properties']['additionalData']['alertProductNames']) + ' |\n' +
            '\n\n')

        # Add raw payload
        if 'first_events' in incident and len(incident['first_events']) > 0:
            description += "#### First event for each alert \n"
            description += '```\n'
            for first_event in incident['first_events']:
                description += json.dumps(first_event, indent=4)
                description += '\n'
            description += '```\n\n'

        return description

    def sentinelIncidentToHiveAlert(self, incident):

        def getHiveSeverity(incident):
            # severity in TheHive is either low, medium or high
            # while severity in Sentinel is from Low to High
            if incident['properties']['severity'] == "Low":
                return 1
            elif incident['properties']['severity'] == "Medium":
                return 2
            elif incident['properties']['severity'] == "High":
                return 3

            return 1

        #
        # Creating the alert
        #

        # Setup Tags
        self.tags = ['AzureSentinel', 'incident', 'Synapse']

        # Check if the automation ids need to be extracted
        if self.cfg.getboolean('AzureSentinel', 'extract_automation_identifiers'):

            # Run the extraction function and add it to the incident data
            # Extract automation ids
            self.tags_extracted = self.tagExtractor(incident, self.cfg.get('AzureSentinel', 'automation_fields'), self.cfg.get('AzureSentinel', 'tag_regexes'))
            # Extract any possible name for a document on a knowledge base
            incident['use_case_names'] = self.tagExtractor(incident, self.cfg.get('AzureSentinel', 'automation_fields'), self.cfg.get('AzureSentinel', 'uc_kb_name_regexes'))
            if len(self.tags_extracted) > 0:
                self.tags.extend(self.tags_extracted)
            else:
                self.logger.info('No match found for incident %s', incident['id'])

        self.defaultObservableDatatype = ['autonomous-system',
                                          'domain',
                                          'file',
                                          'filename',
                                          'fqdn',
                                          'hash',
                                          'ip',
                                          'mail',
                                          'mail_subject',
                                          'other',
                                          'regexp',
                                          'registry',
                                          'uri_path',
                                          'url',
                                          'user-agent']

        # Skip for now
        self.artifacts = []
        for artifact in incident['artifacts']:
            # Add automation tagging and mitre tagging to observables
            if 'tags_extracted' in dir(self) and len(self.tags_extracted) > 0:
                artifact['tags'].extend(self.tags_extracted)
            if 'mitre_tactics' in incident:
                for tactic in incident['mitre_tactics']:
                    if tactic["id"]:
                        artifact['tags'].append(tactic["id"])
            # if 'mitre_techniques' in incident:
            #     artifact['tags'].extend(incident['mitre_techniques'])

            if artifact['dataType'].lower() in self.defaultObservableDatatype:
                self.hiveArtifact = self.TheHiveConnector.craftAlertArtifact(dataType=artifact['dataType'].lower(), data=artifact['data'], message=artifact['message'], tags=artifact['tags'], tlp=artifact['tlp'])
            else:
                artifact['tags'].append('type:' + artifact['dataType'])
                self.hiveArtifact = self.TheHiveConnector.craftAlertArtifact(dataType='other', data=artifact['data'], message=artifact['message'], tags=artifact['tags'], tlp=artifact['tlp'])
            self.artifacts.append(self.hiveArtifact)

        # Retrieve the configured case_template
        self.sentinelCaseTemplate = self.cfg.get('AzureSentinel', 'case_template')

        # Build TheHive alert
        self.alert = self.TheHiveConnector.craftAlert(
            "{}, {}".format(incident['properties']['incidentNumber'], incident['properties']['title']),
            self.craftAlertDescription(incident),
            getHiveSeverity(incident),
            self.azureSentinelConnector.formatDate("alert_timestamp", incident['properties']['createdTimeUtc']),
            self.tags,
            2,
            'New',
            'internal',
            'Azure_Sentinel_incidents',
            str(incident['name']),
            self.artifacts,
            self.sentinelCaseTemplate)

        return self.alert

    def validateRequest(self, request):
        if request.is_json:
            self.content = request.get_json()
            if 'type' in self.content and self.content['type'] == "Active":
                self.workflowReport = self.allIncidents2Alert(self.content['type'])
                if self.workflowReport['success']:
                    return json.dumps(self.workflowReport), 200
                else:
                    return json.dumps(self.workflowReport), 500
            else:
                self.logger.error('Missing type or type is not supported')
                return json.dumps({'sucess': False, 'message': "Missing type or type is not supported"}), 500
        else:
            self.logger.error('Not json request')
            return json.dumps({'sucess': False, 'message': "Request didn't contain valid JSON"}), 400

    def allIncidents2Alert(self, status):
        """
        Get all opened incidents created within Azure Sentinel
        and create alerts for them in TheHive
        """
        self.logger.info('%s.allincident2Alert starts', __name__)

        report = dict()
        report['success'] = True
        report['incidents'] = list()

        try:
            incidentsList = self.azureSentinelConnector.getIncidents()

            # each incidents in the list is represented as a dict
            # we enrich this dict with additional details
            for incident in incidentsList:
                closure_info = self.checkIfInClosedCaseOrAlertMarkedAsRead(incident['name'])
                if closure_info:
                    # Translation table for case statusses
                    closure_status = {
                        "Indeterminate": "Undetermined",
                        "FalsePositive": "FalsePositive",
                        "TruePositive": "TruePositive",
                        "Other": "BenignPositive"
                    }
                    if closure_info['resolutionStatus'] in closure_status:
                        classification = closure_status[closure_info['resolutionStatus']]
                    else:
                        classification = "Undetermined"
                    classification_comment = "Closed by Synapse with summary: {}".format(closure_info['summary'])
                    # Close incident and continue with the next incident
                    self.logger.info("Closed case found for {}. Closing incident...".format(incident['name']))
                    self.azureSentinelConnector.closeIncident(incident['name'], classification, classification_comment)
                    continue

                # Prepare new alert
                incident_report = dict()
                self.logger.debug("incident: %s" % json.dumps(incident, indent=4))

                # Retrieve rule information
                incident['rules'] = []
                rules = incident['properties']['relatedAnalyticRuleIds']
                if len(rules) > 0:
                    for rule in rules:
                        rule_info = self.azureSentinelConnector.getRule(rule)
                        if rule_info:
                            incident['rules'].append(rule_info)

                # Retrieve entity and first event information for each alert
                incident['artifacts'] = []

                datatype_table = {
                    "Account": "user-account",
                    "Host": "fqdn",
                    "Ip": "ip",
                    "File": "filename",
                    "Process": "process_filename",
                    "DNS": "fqdn",
                    "FileHash": "hash",
                    "URL": "url"
                }

                # Parse entities into observables/artifacts
                if 'entities' in incident and incident['entities']:
                    for entity in incident['entities']:
                        # Construct URL for Entity page in Azure portal
                        base_entity_url = self.cfg.get('AzureSentinel', 'entity_base_url')
                        if base_entity_url is None:
                            raise ValueError('Base entity url could not be read from config')
                        entity_url = base_entity_url + entity['name']

                        # Construct dict with relevant Entity data
                        entity_data = json.dumps({'kind': entity['kind'], 'properties': entity['properties']}, indent=2)

                        # Small list of Entity kinds that certainly have a page
                        working_pages = ['account', 'host', 'ip']
                        working_page = True
                        if entity['kind'].lower() not in working_pages:
                            working_page = False
                        
                        # Create message to be added to the observable
                        if working_page:
                            message = f'#### Entity details:\n\n[Entity page]({entity_url})\n\n```\n{entity_data}\n```'
                        else:
                            message = f'#### Entity details:\n\n```\n{entity_data}\n```'
                        
                        # Create observable data structure
                        if entity['kind'] in datatype_table:
                            observable = {
                                'dataType': datatype_table[entity['kind']],
                                'data': entity['properties']['friendlyName'],
                                'message': message,
                                'tags': [],
                                'tlp': 2
                            }
                        else:
                            try:
                                observable = {
                                    'dataType': entity['kind'],
                                    'data': entity['properties']['friendlyName'],
                                    'message': message,
                                    'tags': [],
                                    'tlp': 2
                                }
                            except KeyError as e:
                                self.logger.warning(f"Could not find value for entity {entity['kind']} in alert {incident['name']}")

                        incident['artifacts'].append(observable)

                if incident['related_alerts']:
                    for alert in incident['related_alerts']:                       
                        # Check if alert is from Defender for Endpoint
                        if 'productName' in alert['properties'] and alert['properties']['productName'] == 'Microsoft Defender Advanced Threat Protection':
                            # Add defender id and url to incident
                            incident['defender'] = {
                                'id': alert['properties']['providerAlertId'],
                                'url': 'https://security.microsoft.com/alerts/' + alert['properties']['providerAlertId']
                            }

                theHiveAlert = self.sentinelIncidentToHiveAlert(incident)

                # searching if the incident has already been converted to alert
                query = dict()
                query['sourceRef'] = str(incident['name'])
                self.logger.info('Looking for incident %s in TheHive alerts', str(incident['name']))
                alert_results = self.TheHiveConnector.findAlert(query)
                if len(alert_results) == 0:
                    self.logger.info('incident %s not found in TheHive alerts, creating it', str(incident['name']))

                    try:
                        theHiveEsAlertId = self.TheHiveConnector.createAlert(theHiveAlert)['id']

                        incident_report['raised_alert_id'] = theHiveEsAlertId
                        incident_report['sentinel_incident_id'] = incident['name']
                        incident_report['success'] = True

                    except Exception as e:
                        self.logger.error('%s.allincident2Alert failed', __name__, exc_info=True)
                        incident_report['success'] = False
                        if isinstance(e, ValueError):
                            errorMessage = json.loads(str(e))['message']
                            incident_report['message'] = errorMessage
                        else:
                            incident_report['message'] = str(e) + ": Couldn't raise alert in TheHive"
                        incident_report['incident_id'] = incident['name']
                        # Set overall success if any fails
                        report['success'] = False

                else:
                    self.logger.info('incident %s already imported as alert, checking for updates', str(incident['name']))
                    alert_found = alert_results[0]

                    if self.TheHiveConnector.checkForUpdates(theHiveAlert, alert_found, incident['properties']['incidentNumber']):
                        incident_report['updated_alert_id'] = alert_found['id']
                        incident_report['sentinel_incident_id'] = incident['name']
                        incident_report['success'] = True
                    else:
                        incident_report['sentinel_incident_id'] = incident['name']
                        incident_report['success'] = True
                report['incidents'].append(incident_report)

        except Exception as e:

            self.logger.error('Failed to create alert from Azure Sentinel incident (retrieving incidents failed)', exc_info=True)
            report['success'] = False
            report['message'] = "%s: Failed to create alert from incident" % str(e)

        return report
