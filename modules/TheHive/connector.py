#!/usr/bin/env python3
# -*- coding: utf8 -*-

import logging
import json
import time
import itertools

from core.functions import retrieveSplittedDescription

from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseTask, CaseTaskLog, CaseObservable, AlertArtifact, Alert
from thehive4py.query import Eq

class TheHiveConnector:
    'TheHive connector'

    def __init__(self, cfg):
        self.logger = logging.getLogger('workflows.' + __name__)
        self.cfg = cfg

        self.theHiveApi = self.connect()

    def connect(self):
        self.logger.debug('%s.connect starts', __name__)

        url = self.cfg.get('TheHive', 'url')
        cert = self.cfg.get('TheHive', 'ca', fallback=True)
        api_key = self.cfg.get('TheHive', 'api_key')

        return TheHiveApi(url, api_key, cert=cert)

    # Default error handler for the above requests
    def handleErrors(self, message, response):
        self.logger.error(message)
        try:
            self.logger.error(f"Exception occurred: {json.dumps(response.json())}")
            raise ValueError(json.dumps(response.json(), indent=4, sort_keys=True))
        except json.decoder.JSONDecodeError:
            self.logger.error(f"Exception occurred: {response.text}")
            raise ValueError(response.text)
        except Exception as error:
            self.logger.error(f"Unhandled exception occurred: {error}")

    def searchCaseByDescription(self, string):
        # Search case with a specific string in description
        # Returns the ES case ID

        self.logger.debug('%s.searchCaseByDescription starts', __name__)

        query = dict()
        query['_string'] = 'description:"{}"'.format(string)
        range = 'all'
        sort = []
        response = self.theHiveApi.find_cases(query=query, range=range, sort=sort)

        if response.status_code != 200:
            error = dict()
            error['message'] = 'search case failed'
            error['query'] = query
            error['payload'] = response.json()
            self.logger.error('Query to TheHive API did not return 200')
            raise ValueError(json.dumps(error, indent=4, sort_keys=True))

        if len(response.json()) == 1:
            # One case matched
            esCaseId = response.json()[0]['id']
            return esCaseId
        elif len(response.json()) == 0:
            # No case matched
            return None
        else:
            # Unknown use case
            raise ValueError('unknown use case after searching case by description')

    def getCase(self, caseid):
        self.logger.debug('%s.getCase starts', __name__)

        response = self.theHiveApi.get_case(caseid)

        if response.status_code == 200:
            return response.json()
        else:
            self.handleErrors('Case not found', response)

    def getCaseObservable(self, artifactid):
        self.logger.debug('%s.getCaseObservable starts', __name__)

        response = self.theHiveApi.get_case_observable(artifactid)

        if response.status_code == 200:
            return response.json()
        else:
            self.handleErrors('Artifact not found', response)

    def getCaseObservables(self, caseid):
        self.logger.debug('%s.getCaseObservables starts', __name__)

        response = self.theHiveApi.get_case_observables(caseid)

        if response.status_code == 200:
            return response
        else:
            self.handleErrors('Case not found', response)

    def getCaseTasks(self, caseid):
        self.logger.debug('%s.getCaseTasks starts', __name__)

        response = self.theHiveApi.get_case_tasks(caseid)

        if response.status_code == 200:
            return response
        else:
            self.handleErrors('Case not found', response)

    def craftCase(self, title, description):
        self.logger.debug('%s.craftCase starts', __name__)

        case = Case(title=title,
                    tlp=2,
                    tags=['Synapse'],
                    description=description,
                    )

        return case

    def createCase(self, case):
        self.logger.debug('%s.createCase starts', __name__)

        response = self.theHiveApi.create_case(case)

        if response.status_code == 201:
            esCaseId = response.json()['id']
            createdCase = self.theHiveApi.case(esCaseId)
            return createdCase
        else:
            self.handleErrors('Case creation failed', response)

    def promoteAlertToCase(self, alert_id):
        self.logger.debug('%s.createCaseFromAlert starts', __name__)

        response = self.theHiveApi.promote_alert_to_case(alert_id)

        if response.status_code == 201:
            esCaseId = response.json()['id']
            createdCase = self.theHiveApi.case(esCaseId)
            return createdCase
        else:
            self.handleErrors('Case creation failed', response)

    def updateCase(self, case, fields):
        self.logger.debug('%s.updateCase starts', __name__)

        response = self.theHiveApi.update_case(case, fields)

        if response.status_code == 200:
            return response
        else:
            self.handleErrors('Case update failed', response)

    def closeCase(self, caseid):
        self.logger.debug('%s.closeCase starts', __name__)
        # Create a Case object
        case = Case()
        case.id = caseid
        fields = ['status']
        case.status = "Resolved"
        # Update the case
        self.updateCase(case, fields)

    def assignCase(self, case, assignee):
        self.logger.debug('%s.assignCase starts', __name__)

        esCaseId = case.id
        case.owner = assignee
        self.theHiveApi.update_case(case)

        updatedCase = self.theHiveApi.case(esCaseId)
        return updatedCase

    def craftCommTask(self):
        self.logger.debug('%s.craftCommTask starts', __name__)

        commTask = CaseTask(title='Communication',
                            status='InProgress',
                            owner='synapse')

        return commTask

    def createTask(self, esCaseId, task):
        self.logger.debug('%s.createTask starts', __name__)

        response = self.theHiveApi.create_case_task(esCaseId, task)

        if response.status_code == 201:
            esCreatedTaskId = response.json()['id']
            return esCreatedTaskId
        else:
            self.handleErrors('Task creation failed', response)

    def updateTask(self, task_id, task):
        self.logger.debug('%s.updateTask starts', __name__)

        response = self.theHiveApi.update_case_task(task_id, task)

        if response.status_code == 200:
            return response.json()
        else:
            self.handleErrors('Task update failed', response)

    def craftAlertArtifact(self, **attributes):
        self.logger.debug('%s.craftAlertArtifact starts', __name__)

        alertArtifact = AlertArtifact(dataType=attributes["dataType"], message=attributes["message"], data=attributes["data"], tags=attributes['tags'], tlp=attributes['tlp'])

        return alertArtifact

    def craftTaskLog(self, textLog):
        self.logger.debug('%s.craftTaskLog starts', __name__)

        log = CaseTaskLog(message=textLog)

        return log

    def addTaskLog(self, esTaskId, textLog):
        self.logger.debug('%s.addTaskLog starts', __name__)

        response = self.theHiveApi.create_task_log(esTaskId, textLog)

        if response.status_code == 201:
            esCreatedTaskLogId = response.json()['id']
            return esCreatedTaskLogId
        else:
            self.handleErrors('Task log creation failed', response)

    def getTaskIdByTitle(self, esCaseId, taskTitle):
        self.logger.debug('%s.getTaskIdByName starts', __name__)

        response = self.theHiveApi.get_case_tasks(esCaseId)
        for task in response.json():
            if task['title'] == taskTitle:
                return task['id']

        # No <taskTitle> found
        return None

    def addFileObservable(self, esCaseId, filepath, comment):
        self.logger.debug('%s.addFileObservable starts', __name__)

        file_observable = CaseObservable(dataType='file',
                                         data=[filepath],
                                         tlp=2,
                                         ioc=False,
                                         tags=['Synapse'],
                                         message=comment)

        response = self.theHiveApi.create_case_observable(
            esCaseId, file_observable)

        if response.status_code == 201:
            esObservableId = response.json()['id']
            return esObservableId
        else:
            self.handleErrors('File observable upload failed', response)

    def craftAlert(self, title, description, severity, date, tags, tlp, status, type, source, sourceRef, artifacts, caseTemplate):
        self.logger.debug('%s.craftAlert starts', __name__)

        alert = Alert(title=title,
                      description=description,
                      severity=severity,
                      date=date,
                      tags=tags,
                      tlp=tlp,
                      status=status,
                      type=type,
                      source=source,
                      sourceRef=sourceRef,
                      artifacts=artifacts,
                      caseTemplate=caseTemplate)

        return alert

    def createAlert(self, alert):
        self.logger.debug('%s.createAlert starts', __name__)

        response = self.theHiveApi.create_alert(alert)

        if response.status_code == 201:
            return response.json()
        else:
            self.handleErrors('Create alert failed', response)

    def updateAlert(self, alertid, alert, fields=[]):
        self.logger.debug('%s.updateAlert starts', __name__)

        response = self.theHiveApi.update_alert(alertid, alert, fields=fields)

        if response.status_code == 200:
            return response.json()
        else:
            self.handleErrors('Alert update failed', response)

    def markAlertAsRead(self, alert_id):

        self.logger.debug('%s.markAlertAsRead starts', __name__)

        response = self.theHiveApi.mark_alert_as_read(alert_id)

        if int(response.status_code) in {200, 201, 202, 203, 204, 205}:
            return response.json()
        else:
            self.handleErrors('Could not set alert as read', response)

    def getAlert(self, alert_id):
        self.logger.debug('%s.getAlert starts', __name__)

        response = self.theHiveApi.get_alert(alert_id)

        if response.status_code == 200:
            return response.json()
        else:
            self.handleErrors('Case not found', response)

    def findAlert(self, q):
        """
            Search for alerts in TheHive for a given query

            :param q: TheHive query
            :type q: dict

            :return results: list of dict, each dict describes an alert
            :rtype results: list
        """

        self.logger.debug('%s.findAlert starts', __name__)

        response = self.theHiveApi.find_alerts(query=q)
        if response.status_code == 200:
            results = response.json()
            return results
        else:
            self.handleErrors('findAlert failed', response)

    def findFirstMatchingTemplate(self, searchstring):
        self.logger.debug('%s.findFirstMatchingTemplate starts', __name__)

        query = Eq('status', 'Ok')
        allTemplates = self.theHiveApi.find_case_templates(query=query)
        if allTemplates.status_code != 200:
            raise ValueError('Could not find matching template !')

        for template in allTemplates.json():
            if searchstring in template['name']:
                return template

        return None

    def runAnalyzer(self, cortex_server, observable, analyzer):
        self.logger.debug('%s.runAnalyzer starts', __name__)

        response = self.theHiveApi.run_analyzer(cortex_server, observable, analyzer)

        if response.status_code == 200:
            return response.json()
        else:
            self.handleErrors('Running Analyzer %s failed' % analyzer, response)

    def runResponder(self, object_type, object_id, responder_name):
        self.logger.debug('%s.runResponder starts', __name__)

        responder_id = self.theHiveApi.search_responder_by_name(responder_name)
        response = self.theHiveApi.run_responder(object_type, object_id, responder_id)

        if response.status_code == 200:
            return response.json()
        else:
            self.handleErrors('Running Responder %s failed' % responder_name, response)

    def addObservable(self, esCaseId, datatype, ioc_list, tags, comment):
        self.logger.debug('%s.addObservable starts', __name__)

        ioc_observable = CaseObservable(dataType=datatype,
                                        data=ioc_list,
                                        tlp=2,
                                        ioc=True,
                                        tags=tags,
                                        message=comment
                                        )

        response = self.theHiveApi.create_case_observable(
            esCaseId, ioc_observable)

        if response.status_code == 201:
            esObservableId = response.json()['id']
            return esObservableId
        else:
            self.handleErrors('IOC observable upload failed', response)

    def splitDescription(self, description):
        self.logger.debug(f'Starting splitDescription with {description}.')
        output_dict = {}
        split_description = description.split('#### ')
        # Skip the first part as it is whitespace
        for section in split_description[1:]:
            title, content = section.split('\n', 1)
            if title in output_dict:
                self.logger.warning('Section was already found in the output_dict, it will be overwritten.')
            output_dict[title] = content
        return output_dict

    def compareDescriptions(self, old_description, new_description):
        self.logger.debug('Starting compareDescription.')
        split_current_alert_description = self.splitDescription(old_description)
        split_new_alert_description = self.splitDescription(new_description)
        updated_fields = ''
        for section in split_new_alert_description:
            # Reconstructing the markdown of the updated section
            section_text = f'{section}\n{split_new_alert_description[section]}'
            if section in split_current_alert_description:
                if split_current_alert_description[section] != split_new_alert_description[section]:
                    self.logger.debug('New description differs from old description.')
                    updated_fields += section_text
                else:
                    self.logger.debug('New description is identical to old description.')
            else:
                self.logger.debug('Field name was not found in previous alert')
                updated_fields += section_text
        if (updated_fields == ''):
            self.logger.debug('No updated fields were found.')
            return None
        else:
            return updated_fields

    def checkIfInCase(self, source_ref):
        query = dict()
        query['sourceRef'] = str(source_ref)
        self.logger.debug('Checking if third party ticket({}) is linked to a case'.format(source_ref))
        alert_results = self.findAlert(query)
        if len(alert_results) > 0:
            self.logger.info(f'Alert found with SourceRef "{source_ref}"')
            alert_found = alert_results[0]
            if 'case' in alert_found:
                # Check if alert is present in closed case
                case_found = self.getCase(alert_found['case'])
                return case_found
        # Return False by default
        return False

    def checkIfUpdated(self, current_a, new_a):
        list_of_updated_items = []
        updated_alert_description = None
        # Function to check if the alert that has been created contains new/different data in comparison to the alert that is present
        self.logger.debug("Current alert %s" % current_a)
        self.logger.debug("New alert %s" % new_a)
        for item in sorted(new_a):
            # Skip values that are not required for the compare
            if item == "date":
                continue
            # Artifacts require special attention as these are all separate objects in an array for a new alert. The current alert is a array of dicts
            if item == "artifacts":
                # removing the artifacts with tag uc_enrichment to stop overwriting the artifacts in an alert
                current_a[item] = [i for i in current_a[item] if not ("uc_enrichment" in i['tags'])]
                # If the array is of different size an update is required
                if not len(current_a[item]) == len(new_a[item]):
                    self.logger.info("Length mismatch detected: old length:%s, new length: %s" % (len(current_a[item]), len(new_a[item])))
                    list_of_updated_items.append("artifacts")
                    continue

                # loop through the newly created alert array to extract the artifacts and add them so a separate variable
                for i in range(len(new_a[item])):
                    self.vars_current_artifacts = current_a[item][i]
                    self.vars_new_artifacts = vars(new_a[item][i])

                    # For each artifact loop through the attributes to check for differences
                    for attribute in self.vars_new_artifacts:
                        if self.vars_current_artifacts[attribute] != self.vars_new_artifacts[attribute]:
                            self.logger.debug("Change detected for %s, new value: %s" % (self.vars_current_artifacts[attribute], self.vars_new_artifacts[attribute]))
                            self.logger.debug("old: %s, new: %s" % (self.vars_current_artifacts, self.vars_new_artifacts))
                            list_of_updated_items.append("artifacts")

                # loop through the newly created alert array to extract the artifacts and add them so a separate variable
                # self.diff = list(itertools.filterfalse(lambda x: x in vars(new_a['artifacts']), current_a['artifacts']))
                # if len(self.diff) > 0:
                #     self.logger.debug("Found diff in artifacts: %s" % self.diff)
                #     return True

            if item == "tags":
                # loop through the newly created alert array to extract the tags and add them so a separate variable
                self.diff = list(itertools.filterfalse(lambda x: x in new_a['tags'], current_a['tags']))
                self.diff = self.diff + list(itertools.filterfalse(lambda x: x in current_a['tags'], new_a['tags']))
                if len(self.diff) > 0:
                    self.logger.debug("Found diff in tags: %s" % self.diff)
                    list_of_updated_items.append("tags")

            # Also need to update on severity changes
            if item == "severity" and current_a['severity'] != new_a['severity']:
                list_of_updated_items.append("severity")

            if item == "description":
                # Extract the part that contains the default incident information (Proably requires a small redesign of the description field)
                try:
                    current_alert_description, current_alert_enrichment_table = retrieveSplittedDescription(current_a['description'])
                    enrichment_table_found = True
                except (ValueError, IndexError) as e:
                    current_alert_description = current_a['description']
                    enrichment_table_found = False
                new_alert_description = new_a['description']

                # Compare the two descriptions. If they differ... return true
                if current_alert_description != new_alert_description:
                    updated_alert_description = {}
                    updated_alert_description['new_descriptions'] = self.compareDescriptions(current_alert_description, new_alert_description)

                    # Prepare updated description
                    if enrichment_table_found:
                        updated_alert_description['description'] = new_alert_description + "#### Enriched data" + current_alert_enrichment_table
                    else:
                        updated_alert_description['description'] = new_alert_description
                    list_of_updated_items.append("description")

        return list_of_updated_items, updated_alert_description

    def checkForUpdates(self, alert_generated, alert_found, source_ref):
        query = dict()
        query['sourceRef'] = str(source_ref)

        # Check if alert is already created, but needs updating
        updated_fields, updated_description = self.checkIfUpdated(alert_found, vars(alert_generated))
        if len(updated_fields) > 0:
            self.logger.info(f"Found changes for {alert_found['id']} in these fields: {updated_fields}")

            if updated_description:
                alert_generated.description = updated_description['description']

            # update alert
            self.updateAlert(alert_found['id'], alert_generated, fields=updated_fields)

            # Check to see if a case is present for the alert
            found_case = self.checkIfInCase(query['sourceRef'])

            # WORKAROUND: close case if they are closed with status Duplicate (aka merged into another case)
            if found_case is not False and 'resolutionStatus' in found_case and found_case['resolutionStatus'] == "Duplicated":
                self.logger.info(f"Closing original case({found_case['id']}) as The Hive has reopened it")
                self.closeCase(found_case['id'])

            if updated_description and found_case is not False:
                self.logger.info(f'Alert {alert_found["id"]} is part of an existing case: {found_case["id"]}')
                # if case is present. Find and replace the new description field content there as well
                if 'resolutionStatus' in found_case and found_case['resolutionStatus'] == "Duplicated":
                    self.logger.info(f'Update mechanism found merged case {found_case["id"]}, looking for top merged case')
                    merged_case_found = self.getFinalMergedCase(found_case)
                    self.logger.info(f'Found the top merged case {merged_case_found["id"]}, adding update there')
                    if merged_case_found:
                        found_case = merged_case_found
                self.addUpdateToCase(found_case, source_ref, updated_description['new_descriptions'])
            else:
                self.logger.info(f'Alert {alert_found["id"]} was not found in a case.')
                return False
            return True
        else:
            self.logger.info("No changes found for %s" % alert_found['id'])
            return False

    def addUpdateToCase(self, case, incident_number, updated_description):
        task_title = f'Updates for alert {incident_number}'
        current_tasks = self.getCaseTasks(case['id'])
        update_task_dict = None
        for task in current_tasks.json():
            if task['title'] == task_title:
                update_task_dict = task
                self.logger.debug(f'Found "Updates" task:\n{update_task_dict}')
        if update_task_dict is None:
            self.logger.debug(f'Update task not found in case {case["id"]}, creating "Update" task')
            update_task = CaseTask(title=task_title,
                                   status='InProgress',
                                   flag=True,
                                   owner='synapse',
                                   group='Updates',
                                   startDate=int(time.time() * 1000))
            task_id = self.createTask(case['id'], update_task)
        else:
            task_id = update_task_dict['id']
            update_task = CaseTask(title=task_title, flag=True)
            self.updateTask(update_task_dict['id'], update_task)
        self.logger.info(f'Adding update to task {task_title} for case {case["id"]}')
        self.addTaskLog(task_id, self.craftTaskLog(updated_description))
