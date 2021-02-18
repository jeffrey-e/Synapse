#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os, sys
import logging
import json
import hashlib
import re
import time
from calendar import timegm
from time import sleep
from builtins import str as unicode
from core.functions import getConf
from core.integration import Main
from modules.TheHive.connector import TheHiveConnector

class Integration(Main):

    def __init__(self):
        super().__init__()
        self.theHiveConnector = TheHiveConnector(self.cfg)
    
    def __findartifacts(self, value):
        """Checks if the given value is contains regexes
        :param value: The value to check
        :type value: str or number
        :return: Data type of value, if known, else empty string
        :rtype: str
        """

        #Init regexes
        self.logger.info("Preparing regex statements")

        #### Generic regexes
        
        # IPv4
        regex = [{
            'types': ['ip'],
            'regex': re.compile(r'(?:^|\D)((?:25[0-5]|2[0-4]\d|[1]\d\d|[1-9]\d|[0-9])\.(?:25[0-5]|2[0-4]\d|[1]\d\d|[1-9]\d|[0-9])\.(?:25[0-5]|2[0-4]\d|[1]\d\d|[1-9]\d|[0-9])\.(?:25[0-5]|2[0-4]\d|[1]\d\d|[1-9]\d|[0-9]))(?:\D|$)', re.MULTILINE)
        }]

        # URL
        regex.append({
            'types': ['url','fqdn','domain','uri_path'],
            'regex': re.compile(r'((?:http|https):\/\/((?:(?:.*?)\.)?(.*?(?:\.\w+)+))\/?([a-zA-Z0-9\/\-\_\.\~\=\?]+\??)?)', re.MULTILINE)
        })

        # mail
        regex.append({
            'types': ['mail','domain'],
            'regex': re.compile(r'((?:[a-zA-Z0-9\/\-\_\.\+]+)@{1}([a-zA-Z0-9\-\_]+\.[a-zA-Z0-9\-\_\.]+)+)', re.MULTILINE)
        })

        found_observables = []
        if isinstance(value, (str, unicode)):
            for r in regex:
                matches = re.findall(r.get('regex'), value)
                if len(matches) > 0:
                    
                    for found_observable in matches:
                        if isinstance(found_observable, tuple):
                            i = 0
                            for groups in found_observable:
                                found_observables.append({
                                    'type': r.get('types')[i],
                                    'value': found_observable[i]
                                    })
                                i += 1
                        else:
                            found_observables.append({
                                'type': r.get('types')[0],
                                'value': found_observable
                                })
            if len(found_observables) > 0:
                return found_observables
            else:
                return []

    def validateRequest(self, request):
        self.logger.info("Received JSON request")
        self.logger.debug('request: %s' % request.get_data())
        if request.is_json:
            content = request.get_json()
            workflowReport = self.json2Alert(content)
            if workflowReport['success']:
                return json.dumps(workflowReport), 200
            else:
                return json.dumps(workflowReport), 500
        else:
            self.logger.error('Not a json request: %s' % request.get_data())
            return json.dumps({'sucess':False, 'message':"Request didn't contain valid JSON"}), 400

    def JSONToHiveAlert(self, alert_data):
        #
        # Creating the alert
        #

        # Setup Tags
        tags = ['JSON', 'Synapse']

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
                                    'regexp',
                                    'registry',
                                    'uri_path',
                                    'url',
                                    'user-agent']
        found_artifacts = self.__findartifacts(alert_data['description'])
        if 'rule_id' in alert_data:
            uc_tags = alert_data['rule_id'].split(",")
            uc_tags = list(set(uc_tags) | set(alert_data['rule_triggered_id'].split(",")))
            tags.extend(uc_tags)
        artifacts = []
        for found_artifact in found_artifacts:
            if not 'tags' in found_artifact:
                found_artifact['tags'] = list()
            found_artifact['tags'].append('type:' + found_artifact['type'])

            if found_artifact['type'] in defaultObservableDatatype:
                hiveArtifact = self.theHiveConnector.craftAlertArtifact(dataType=found_artifact['type'], data=found_artifact['value'], message='', tags=found_artifact['tags'])
            else:
                hiveArtifact = self.theHiveConnector.craftAlertArtifact(dataType='other', data=found_artifact['data'], message='', tags=found_artifact['tags'])
            artifacts.append(hiveArtifact)

        #Convert timestamp to epoch
        if 'start_time' in alert_data:
            utc_time = time.strptime(alert_data['start_time'], "%Y-%m-%dT%H:%M:%S.%fZ")
            epoch_start_time = timegm(utc_time) * 1000
        else:
            epoch_start_time = timegm(time.gmtime()) * 1000

        # Build TheHive alert
        alert = self.theHiveConnector.craftAlert(
            alert_data['title'],
            alert_data['description'],
            1,
            epoch_start_time,
            tags,
            2,
            'Imported',
            'internal',
            alert_data['type'],
            str(alert_data['sourceRef']),
            artifacts,
            alert_data['case_template'])

        return alert

    def json2Alert(self, event):
        """
        Parse the received ml watcher notification
        Original example logstash output:

        Nice example input:
        {
                "title": "test postman",
                "description": "*test1 \n\n test",
                "type": "postman",
                "source": "laptop",
                "sourceRef": "2",
                "severity": 4
                ""
            }
        """
        #self.logger = logging.getLogger(__name__)
        self.logger.info('%s.json2Alert starts', __name__)

        report = dict()
        report['success'] = True

        try:
            #Initiate dict for the alert
            alert_content = dict()

            #Check for a proper id
            id = hashlib.sha1(json.dumps(event).encode('utf-8')).hexdigest()

            for key,value in alert_content.items():
            #Validate attributes
                if not key in event:
                    if key == 'sourceRef':
                        alert_content['sourceRef'] = id
                    elif key == "title":
                        self.logger.error("Could not find a title for this event: {}".format(event))
                        report['success'] = False
                    else:
                        self.logger.warning("Could not find a {} for this event '{}', using default value".format(key, event['title']))
                        if key == 'description':
                            alert_content[key] = "No description"
                        if key == 'source':
                            alert_content[key] = "Synapse"
                        if key == 'severity':
                            alert_content[key] = "1"
                else:
                    alert_content[key] = str(event[key])
            
            results = self.theHiveConnector.findAlert(alert_content['sourceRef'])
            if len(results) == 0:
                self.logger.info('Json Alert %s not found in TheHive alerts, creating it', str(event['sourceRef']))
                event_report = dict()
                
                try:
                    theHiveAlert = self.JSONToHiveAlert(event)
                    theHiveEsAlertId = self.theHiveConnector.createAlert(theHiveAlert)

                    event_report['raised_alert_id'] = theHiveEsAlertId
                    event_report['alert_id'] = event['sourceRef']
                    event_report['success'] = True

                except Exception as e:
                    self.logger.error('%s.json2Alert failed', __name__, exc_info=True)
                    event_report['success'] = False
                    if isinstance(e, ValueError):
                        errorMessage = json.loads(str(e))['message']
                        event_report['message'] = errorMessage
                    else:
                        event_report['message'] = str(e) + ": Couldn't raise alert in TheHive"
                    event_report['alert_id'] = event['sourceRef']
                    # Set overall success if any fails
                    report['success'] = False

                report['event'] = event_report
            else:
                self.logger.info('JSON Alert %s already imported as alert', str(event['sourceRef']))

        except Exception as e:

                self.logger.error('Failed to create alert from JSON Alert', exc_info=True)
                report['success'] = False
                report['message'] = "%s: Failed to create alert from JSON Alert" % str(e)
        
        return report