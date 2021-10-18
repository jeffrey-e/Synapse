#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os
import sys
import logging
import copy
import json
import datetime
import re
from core.integration import Main
from modules.QRadar.connector import QRadarConnector
from modules.TheHive.connector import TheHiveConnector
from time import sleep

class Integration(Main):

    def __init__(self):
        super().__init__()
        self.qradarConnector = QRadarConnector(self.cfg)
        self.TheHiveConnector = TheHiveConnector(self.cfg)

    def enrichOffense(self, offense):

        enriched = copy.deepcopy(offense)

        artifacts = []

        enriched['offense_type_str'] = \
            self.qradarConnector.getOffenseTypeStr(offense['offense_type'])

        # Add the offense source explicitly
        if enriched['offense_type_str'] == 'Username':
            artifacts.append({'data': offense['offense_source'], 'dataType': 'user-account', 'message': 'Offense Source', 'tags': ['QRadar']})

        # Add the local and remote sources
        # scrIps contains offense source IPs
        srcIps = list()
        # dstIps contains offense destination IPs
        dstIps = list()
        # srcDstIps contains IPs which are both source and destination of offense
        srcDstIps = list()
        for ip in self.qradarConnector.getSourceIPs(enriched):
            srcIps.append(ip)

        for ip in self.qradarConnector.getLocalDestinationIPs(enriched):
            dstIps.append(ip)

        # making copies is needed since we want to
        # access and delete data from the list at the same time
        s = copy.deepcopy(srcIps)
        d = copy.deepcopy(dstIps)

        for srcIp in s:
            for dstIp in d:
                if srcIp == dstIp:
                    srcDstIps.append(srcIp)
                    srcIps.remove(srcIp)
                    dstIps.remove(dstIp)

        for ip in srcIps:
            artifacts.append({'data': ip, 'dataType': 'ip', 'message': 'Source IP', 'tags': ['QRadar', 'src']})
        for ip in dstIps:
            artifacts.append({'data': ip, 'dataType': 'ip', 'message': 'Local destination IP', 'tags': ['QRadar', 'dst']})
        for ip in srcDstIps:
            artifacts.append({'data': ip, 'dataType': 'ip', 'message': 'Source and local destination IP', 'tags': ['QRadar', 'src', 'dst']})

        # Parse offense types to add the offense source as an observable when a valid type is used
        for offense_type, extraction_config in self.cfg.get('QRadar', 'observables_in_offense_type', fallback={}).items():
            if enriched['offense_type_str'] == offense_type:
                if isinstance(extraction_config, str):
                    observable_type = extraction_config
                    artifacts.append({'data': enriched['offense_source'], 'dataType': observable_type, 'message': 'QRadar Offense source', 'tags': ['QRadar']})
                elif isinstance(extraction_config, list):
                    for extraction in extraction_config:
                        regex = re.compile(extraction['regex'])
                        matches = regex.findall(str(enriched['offense_source']))
                        if len(matches) > 0:
                            # if isinstance(found_observable, tuple): << Fix later loop through matches as well
                            for match_group, observable_type in extraction['match_groups'].items():
                                try:
                                    artifacts.append({'data': matches[0][match_group], 'dataType': observable_type, 'message': 'QRadar Offense Type based observable', 'tags': ['QRadar', 'offense_type']})
                                except Exception as e:
                                    self.logger.warning("Could not find match group {} in {}".format(match_group, enriched['offense_type_str']))
                else:
                    self.logger.error("Configuration for observables_in_offense_type is wrongly formatted. Please fix this to enable this functionality")

        # Remove observables that are to be excluded based on the configuration
        artifacts = self.checkObservableExclusionList(artifacts)

        # Match observables against the TLP list
        artifacts = self.checkObservableTLP(artifacts)

        # Add all the observables
        enriched['artifacts'] = artifacts

        # Add rule names to offense
        enriched['rules'] = self.qradarConnector.getRuleNames(offense)

        # waiting 1s to make sure the logs are searchable
        sleep(1)
        # adding the first 3 raw logs
        enriched['logs'] = self.qradarConnector.getOffenseLogs(enriched)

        return enriched

    def qradarOffenseToHiveAlert(self, offense):

        def getHiveSeverity(offense):
            # severity in TheHive is either low, medium or high
            # while severity in QRadar is from 1 to 10
            # low will be [1;4] => 1
            # medium will be [5;6] => 2
            # high will be [7;10] => 3
            if offense['severity'] < 5:
                return 1
            elif offense['severity'] < 7:
                return 2
            elif offense['severity'] < 11:
                return 3

            return 1

        #
        # Creating the alert
        #

        # Setup Tags
        tags = ['QRadar', 'Offense', 'Synapse']
        # Add the offense type as a tag
        if 'offense_type_str' in offense:
            tags.append("qr_offense_type: {}".format(offense['offense_type_str']))

        # Check if the automation ids need to be extracted
        if self.cfg.getboolean('QRadar', 'extract_automation_identifiers'):

            # Run the extraction function and add it to the offense data
            # Extract automation ids
            tags_extracted = self.tagExtractor(offense, self.cfg.get('QRadar', 'automation_fields'), self.cfg.get('QRadar', 'tag_regexes'))
            # Extract any possible name for a document on a knowledge base
            offense['use_case_names'] = self.tagExtractor(offense, self.cfg.get('QRadar', 'automation_fields'), self.cfg.get('QRadar', 'uc_kb_name_regexes'))
            if len(tags_extracted) > 0:
                tags.extend(tags_extracted)
            else:
                self.logger.info('No match found for offense %s', offense['id'])

        # Check if the mitre ids need to be extracted
        if self.cfg.getboolean('QRadar', 'extract_mitre_ids'):
            # Extract mitre tactics
            offense['mitre_tactics'] = self.tagExtractor(offense, ["rules"], [r'[tT][aA]\d{4}'])
            if 'mitre_tactics' in offense:
                tags.extend(offense['mitre_tactics'])

            # Extract mitre techniques
            offense['mitre_techniques'] = self.tagExtractor(offense, ["rules"], [r'[tT]\d{4}'])
            if 'mitre_techniques' in offense:
                tags.extend(offense['mitre_techniques'])

        if "categories" in offense:
            for cat in offense['categories']:
                tags.append(cat)

        defaultObservableDatatype = ['autonomous-system',
                                     'domain',
                                     'file',
                                     'filename',
                                     'fqdn',
                                     'hash',
                                     'ip',
                                     'mail',
                                     'mail_subject',
                                     'other',
                                     'process_filename',
                                     'regexp',
                                     'registry',
                                     'uri_path',
                                     'url',
                                     'user-account',
                                     'user-agent']

        artifacts = []
        for artifact in offense['artifacts']:
            # Add automation tagging and mitre tagging to observables
            if len(tags_extracted) > 0:
                artifact['tags'].extend(tags_extracted)
            if 'mitre_tactics' in offense:
                artifact['tags'].extend(offense['mitre_tactics'])
            if 'mitre_techniques' in offense:
                artifact['tags'].extend(offense['mitre_techniques'])

            if artifact['dataType'] in defaultObservableDatatype:
                hiveArtifact = self.TheHiveConnector.craftAlertArtifact(dataType=artifact['dataType'], data=artifact['data'], message=artifact['message'], tags=artifact['tags'], tlp=artifact['tlp'])
            else:
                artifact['tags'].append('type:' + artifact['dataType'])
                hiveArtifact = self.TheHiveConnector.craftAlertArtifact(dataType='other', data=artifact['data'], message=artifact['message'], tags=artifact['tags'], tlp=artifact['tlp'])
            artifacts.append(hiveArtifact)

        # Retrieve the configured case_template
        qradarCaseTemplate = self.cfg.get('QRadar', 'case_template')

        # Build TheHive alert
        alert = self.TheHiveConnector.craftAlert(
            "{}, {}".format(offense['id'], offense['description']),
            self.craftAlertDescription(offense),
            getHiveSeverity(offense),
            offense['start_time'],
            tags,
            2,
            'Imported',
            'internal',
            'QRadar_Offenses',
            str(offense['id']),
            artifacts,
            qradarCaseTemplate)

        return alert

    def validateRequest(self, request):
        if request.is_json:
            content = request.get_json()
            if 'timerange' in content:
                workflowReport = self.allOffense2Alert(content['timerange'])
                if workflowReport['success']:
                    return json.dumps(workflowReport), 200
                else:
                    return json.dumps(workflowReport), 500
            else:
                self.logger.error('Missing <timerange> key/value')
                return json.dumps({'sucess': False, 'message': "timerange key missing in request"}), 500
        else:
            self.logger.error('Not json request')
            return json.dumps({'sucess': False, 'message': "Request didn't contain valid JSON"}), 400

    def allOffense2Alert(self, timerange):
        """
        Get all openned offense created within the last
        <timerange> minutes and creates alerts for them in
        TheHive
        """
        self.logger.info('%s.allOffense2Alert starts', __name__)

        report = dict()
        report['success'] = True
        report['offenses'] = list()

        try:
            offensesList = self.qradarConnector.getOffenses(timerange)
            # Check for offenses that should have been closed
            for offense in offensesList:
                closure_info = self.checkIfInClosedCaseOrAlertMarkedAsRead(offense['id'])
                if closure_info:
                    # Close incident and continue with the next incident
                    self.logger.info("Closed case found for {}. Closing offense...".format(offense['id']))
                    self.qradarConnector.closeOffense(offense['id'])
                    continue

                matched = False
                # Filter based on regexes in configuration
                for offense_exclusion_regex in self.cfg.get('QRadar', 'offense_exclusion_regexes', fallback=[]):
                    self.logger.debug("Offense exclusion regex found '{}'. Matching against offense {}".format(offense_exclusion_regex, offense['id']))
                    regex = re.compile(offense_exclusion_regex, flags=re.I)
                    if regex.match(offense['description']):
                        self.logger.debug("Found exclusion match for offense {} and regex {}".format(offense['id'], offense_exclusion_regex))
                        matched = True
                if matched:
                    continue

                # Prepare new alert
                offense_report = dict()
                self.logger.debug("offense: %s" % offense)
                self.logger.info("Enriching offense...")
                enrichedOffense = self.enrichOffense(offense)
                self.logger.debug("Enriched offense: %s" % enrichedOffense)
                theHiveAlert = self.qradarOffenseToHiveAlert(enrichedOffense)

                # searching if the offense has already been converted to alert
                query = dict()
                query['sourceRef'] = str(offense['id'])
                self.logger.info('Looking for offense %s in TheHive alerts', str(offense['id']))
                results = self.TheHiveConnector.findAlert(query)
                if len(results) == 0:
                    self.logger.info('Offense %s not found in TheHive alerts, creating it', str(offense['id']))

                    try:
                        theHiveEsAlertId = self.TheHiveConnector.createAlert(theHiveAlert)['id']

                        offense_report['raised_alert_id'] = theHiveEsAlertId
                        offense_report['qradar_offense_id'] = offense['id']
                        offense_report['success'] = True

                    except Exception as e:
                        self.logger.error('%s.allOffense2Alert failed', __name__, exc_info=True)
                        offense_report['success'] = False
                        if isinstance(e, ValueError):
                            errorMessage = json.loads(str(e))['message']
                            offense_report['message'] = errorMessage
                        else:
                            offense_report['message'] = str(e) + ": Couldn't raise alert in TheHive"
                        offense_report['offense_id'] = offense['id']
                        # Set overall success if any fails
                        report['success'] = False

                    report['offenses'].append(offense_report)
                else:
                    self.logger.info('Offense %s already imported as alert, checking for updates', str(offense['id']))
                    alert_found = results[0]

                    if self.TheHiveConnector.checkForUpdates(theHiveAlert, alert_found, offense['id']):
                        offense_report['updated_alert_id'] = alert_found['id']
                        offense_report['qradar_offense_id'] = offense['id']
                        offense_report['success'] = True
                    else:
                        offense_report['qradar_offense_id'] = offense['id']
                        offense_report['success'] = True
                report['offenses'].append(offense_report)
                ##########################################################

        except Exception as e:
            self.logger.error('Failed to create alert from QRadar offense (retrieving offenses failed)', exc_info=True)
            report['success'] = False
            report['message'] = "%s: Failed to create alert from offense" % str(e)

        return report

    def craftAlertDescription(self, offense):
        """
            From the offense metadata, crafts a nice description in markdown
            for TheHive
        """
        self.logger.debug('craftAlertDescription starts')

        # Start empty
        description = ""

        # Add url to Offense
        qradar_ip = self.cfg.get('QRadar', 'server')
        url = ('[%s](https://%s/console/qradar/jsp/QRadar.jsp?appName=Sem&pageId=OffenseSummary&summaryId=%s)' % (str(offense['id']), qradar_ip, str(offense['id'])))

        description += '#### Offense: \n - ' + url + '\n\n'

        # Format associated rules
        rule_names_formatted = "#### Rules triggered: \n"
        rules = offense['rules']
        if len(rules) > 0:
            for rule in rules:
                if 'name' in rule:
                    rule_names_formatted += "- %s \n" % rule['name']
                else:
                    continue

        # Add rules overview to description
        description += rule_names_formatted + '\n\n'

        # Format associated documentation
        uc_links_formatted = "#### Use Case documentation: \n"
        kb_url = self.cfg.get('QRadar', 'kb_url')
        if 'use_case_names' in offense and offense['use_case_names']:
            for uc in offense['use_case_names']:
                replaced_kb_url = kb_url.replace('<uc_kb_name>', uc)
                uc_links_formatted += f"- [{uc}]({replaced_kb_url}) \n"

            # Add associated documentation
            description += uc_links_formatted + '\n\n'

        # Add mitre Tactic information
        mitre_ta_links_formatted = "#### MITRE Tactics: \n"
        if 'mitre_tactics' in offense and offense['mitre_tactics']:
            for tactic in offense['mitre_tactics']:
                mitre_ta_links_formatted += "- [%s](%s/%s) \n" % (tactic, 'https://attack.mitre.org/tactics/', tactic)

            # Add associated documentation
            description += mitre_ta_links_formatted + '\n\n'

        # Add mitre Technique information
        mitre_t_links_formatted = "#### MITRE Techniques: \n"
        if 'mitre_techniques' in offense and offense['mitre_techniques']:
            for technique in offense['mitre_techniques']:
                mitre_t_links_formatted += "- [%s](%s/%s) \n" % (technique, 'https://attack.mitre.org/techniques/', technique)

            # Add associated documentation
            description += mitre_t_links_formatted + '\n\n'

        # Add offense details table
        description += (
            '#### Summary:\n\n' +
            '|                         |               |\n' +
            '| ----------------------- | ------------- |\n' +
            '| **Start Time**          | ' + str(self.qradarConnector.formatDate(offense['start_time'])) + ' |\n' +
            '| **Offense ID**          | ' + str(offense['id']) + ' |\n' +
            '| **Description**         | ' + str(offense['description'].replace('\n', '')) + ' |\n' +
            '| **Offense Type**        | ' + str(offense['offense_type_str']) + ' |\n' +
            '| **Offense Source**      | ' + str(offense['offense_source']) + ' |\n' +
            '| **Destination Network** | ' + str(offense['destination_networks']) + ' |\n' +
            '| **Source Network**      | ' + str(offense['source_network']) + ' |\n\n\n' +
            '\n\n\n\n')

        # Add raw payload
        description += '#### Payload:\n```\n'
        for log in offense['logs']:
            description += log['utf8_payload'] + '\n'
        description += '```\n\n'

        return description
