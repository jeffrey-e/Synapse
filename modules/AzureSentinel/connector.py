import logging
import requests
import json
import re
from datetime import datetime
from dateutil import tz
from modules.AzureSentinel.incidentfilter import IncidentFilter

class AzureSentinelConnector:
    'AzureSentinelConnector connector'

    def __init__(self, cfg):
        """
            Class constuctor

            :param cfg: synapse configuration
            :type cfg: ConfigParser

            :return: Object AzureSentinelConnector
            :rtype: AzureSentinelConnector
        """

        self.logger = logging.getLogger(__name__)
        self.cfg = cfg
        self.subscription_id = self.cfg.get('AzureSentinel', 'subscription_id')
        self.resource_group = self.cfg.get('AzureSentinel', 'resource_group')
        self.workspace = self.cfg.get('AzureSentinel', 'workspace')
        self.tenant_id = self.cfg.get('AzureSentinel', 'tenant_id')
        self.client_id = self.cfg.get('AzureSentinel', 'client_id')
        self.client_secret = self.cfg.get('AzureSentinel', 'client_secret')
        self.base_url = 'https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.OperationalInsights/workspaces/{}/providers/Microsoft.SecurityInsights'.format(self.subscription_id, self.resource_group, self.workspace)
        self.bearer_token = self.getBearerToken()

        # Loading filter config
        self.incidentFilter = IncidentFilter(self.cfg)

    def getBearerToken(self):
        self.url = 'https://login.microsoftonline.com/{}/oauth2/token'.format(self.tenant_id)
        self.data = 'grant_type=client_credentials&client_id={}&client_secret={}&resource=https%3A%2F%2Fmanagement.azure.com&undefined='.format(self.client_id, self.client_secret)
        # Adding empty header as parameters are being sent in payload
        self.headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "cache-control": "no-cache",
        }
        try:
            self.response = requests.post(self.url, self.data, headers=self.headers, timeout=60)
            self.logger.debug("Retrieved token: {}".format(self.response.json()["access_token"]))
            return self.response.json()["access_token"]
        except Exception as e:
            self.logger.error("Could not get Bearer token from Azure Sentinel: {}".format(e))

    def azureRequest(self, method, url, data=None, bearer_token_regenerated=False):
        self.logger.debug("Received the following request to perform: {}".format(url))
        if data:
            self.logger.debug("Received the following request body: {}".format(data))

        # Prepare return dict
        result = {
            "success": False,
            "status_code": 0,
            "json": {}
        }

        # Adding empty header as parameters are being sent in payload
        self.headers = {
            "Authorization": "Bearer " + self.bearer_token,
            "cache-control": "no-cache",
        }
        try:
            response = requests.request(method, url, headers=self.headers, json=data, timeout=60)
            result['status_code'] = response.status_code
            try:
                result['json'] = response.json()
            except Exception:
                self.logger.debug("no json found in request body or could not parse the json")
            if 'error' in response.json() and response.status_code != 401:
                self.logger.error("Azure Sentinel prompted an error code '{}' with full error: '{}'".format(response.json()['error']['code'], response.json()['error']))
                return result

            if (response.status_code == 200):
                result['success'] = True
                self.logger.debug("the following response was received: {}".format(result['json']))
                return result
            elif response.status_code == 401:
                raise ConnectionRefusedError(response.content)
            # Retrieve alert information. Added a workaround to fix the delay in alert entity retrieval that causes a not found error sometimes
            elif response.status_code == 404:
                return result
            else:
                raise SentinelUnhandledReturnCode
        except ValueError as e:
            self.logger.error('AzureSentinel returned http {} with the following body: {}'.format(response.status_code, e))
            return result
        except ConnectionRefusedError as e:
            # Supporting regeneration of the token automatically. Will try once and will fail after
            if not bearer_token_regenerated:
                self.logger.info("Bearer token expired. Generating a new one")
                self.bearer_token = self.getBearerToken()
                return self.azureRequest(method, url, data, bearer_token_regenerated=True)
            else:
                self.logger.error("An attempt was made to regenerate the Bearer token, but the request still fails with code 401: {}".format(e))
                return result
        except Exception as e:
            self.logger.error("Could not retrieve data from Azure Sentinel: {}".format(e), exc_info=True)
            return result

    def formatDate(self, target, sentinelTimeStamp):
        # Example: 2020-10-22T12:55:27.9576603Z << can also be six milliseconds. Cropping the timestamp therefore...
        # Define timezones
        current_timezone = tz.gettz('UTC')

        # Retrieve timezone from config or use local time (None)
        configured_timezone = self.cfg.get('AzureSentinel', 'timezone', fallback=None)
        self.logger.debug("Found timezone to convert to: {}".format(configured_timezone))
        new_timezone = tz.gettz(configured_timezone)

        # Parse timestamp received from Sentinel cropping to six milliseconds as 7 is not supported
        self.logger.debug("Cropped timestamp from: {} to: {}".format(sentinelTimeStamp, sentinelTimeStamp[0:19]))
        formatted_time = datetime.strptime(sentinelTimeStamp[0:19], "%Y-%m-%dT%H:%M:%S")
        utc_formatted_time = formatted_time.replace(tzinfo=current_timezone)

        # Convert to configured timezone
        ntz_formatted_time = utc_formatted_time.astimezone(new_timezone)

        if target == "description":

            # Create a string from time object
            string_formatted_time = ntz_formatted_time.strftime('%Y-%m-%d %H:%M:%S')

        elif target == "alert_timestamp":
            # Create a string from time object
            string_formatted_time = ntz_formatted_time.timestamp() * 1000

        self.logger.debug("Changed time from {} to {}".format(sentinelTimeStamp, string_formatted_time))
        return string_formatted_time

    def getIncident(self, incident_id):
        url = self.base_url + '/incidents/{}?api-version=2020-01-01'.format(incident_id)
        response = self.azureRequest("get", url)
        if response['success']:
            return response['json']
        else:
            self.logger.error('Failed retrieve incident %s', incident_id, exc_info=True)
            return False

    def getIncidents(self):
        # Variable required for handling regeneration of the Bearer token
        self.bearer_token_regenerated = False

        # Empty array for incidents
        unfiltered_incidents = []
        incidents = []

        url = self.base_url + '/incidents?api-version=2020-01-01&%24filter=(properties%2Fstatus%20eq%20\'New\'%20or%20properties%2Fstatus%20eq%20\'Active\')&%24orderby=properties%2FcreatedTimeUtc%20desc'

        response = self.azureRequest("get", url)
        if response['success']:
            results = response['json']
            unfiltered_incidents.extend(results["value"])
            # Lazy loop to grab all incidents
            while 'nextLink' in results:
                url = results['nextLink']
                response = self.azureRequest("get", url)
                if response['success']:
                    results = response['json']
                    # Continue if an invalid response is returned, otherwise the whole ingest will shut down
                    if 'value' not in results:
                        continue
                    unfiltered_incidents.extend(results["value"])

            # Add alert info to incidents
            enriched_incidents = self.enrichIncidentsWithAlerts(unfiltered_incidents)

            if self.cfg.getboolean('AzureSentinel', 'filter_incidents'):
                # Run inclusion/exclusion logic
                for incident in enriched_incidents:
                    # Add entity information to incident
                    incident['entities'] = self.getEntities(incident['name'])                   

                    passed_filter, filter_message = self.incidentFilter.filterIncident(incident)
                    if passed_filter is False:
                        if self.cfg.getboolean('AzureSentinel', 'close_filtered_incident'):
                            alert_products_to_auto_close = self.cfg.get('AzureSentinel', 'close_only_for_alert_products')
                            if alert_products_to_auto_close:
                                can_close = []
                            # Check to see if the alert products are allowed to be closed
                            if not self.incidentFilter.checkProductFilter(alert_products_to_auto_close, incident['properties']['additionalData']['alertProductNames']):
                                continue
                            else:
                                # Close incident when filtered as it should no longer be required
                                self.logger.info(f"Closing incident {incident['name']} due to a match in the filter")
                                self.closeIncident(incident['name'], "Undetermined", f"Closed by Synapse due to incident filtering.\nReason:\n{filter_message}")
                        else:
                            self.logger.info(f"Ignoring incident {incident['name']} due to a match in the filter")
                        continue
                    else:
                        self.logger.info(f"Incident {incident['name']} not filtered, adding incident to list")
                        # Add non filtered incident
                        incidents.append(incident)
            else:
                for incident in enriched_incidents:
                    # Add entity information to incident
                    incident['entities'] = self.getEntities(incident['name'])
                    incidents.append(incident)
        else:
            self.logger.error('Failed retrieve incidents', exc_info=True)

        return incidents

    def enrichIncidentsWithAlerts(self, incidents):
        enriched_incidents = []
        for incident in incidents:
            enriched_incidents.append(self.enrichIncident(incident))
        return enriched_incidents
            
    def enrichIncident(self, incident):
        related_alerts = self.getRelatedAlerts(incident['name'])
        # Enrich the alert if related alerts were found, otherwise it is returned unchanged.
        if related_alerts is not False:
            enriched_alerts = []
            # Enrich each alert with extra info.
            for alert in related_alerts:
                enriched_alerts.append(self.enrichAlert(alert))
            incident['related_alerts'] = enriched_alerts
            incident['first_events'] = []
            incident['custom_details'] = []
            # Add first event for each alert if found.
            for alert in incident['related_alerts']:
                if 'first_event' in alert:
                    incident['first_events'].append(alert['first_event'])
                if 'custom_details' in alert:
                    incident['custom_details'].append(alert['custom_details'])
        # Return the incident unchanged as default behaviour.
        return incident
                    
    def enrichAlert(self, alert):
        # Only enrich Azure Sentinel alerts (nothing to be found in other sources).
        if self.incidentFilter.checkProductFilter('Azure Sentinel', [alert['properties']['productName']]) is True:
            enriched_alert = self.getAlertDetails(alert)
            if enriched_alert is not False:
                if 'query' in enriched_alert:
                    first_event = self.getFirstEventForAlert(enriched_alert)
                    if first_event is not False:
                        enriched_alert['first_event'] = first_event
                    else:
                        self.logger.debug(f'Could not find raw events for {alert["name"]}')
                else:
                     self.logger.debug(f'Could not find alert query {alert["name"]}')
                return enriched_alert
        # Return the alert unchanged as default behaviour.
        return alert

    def getAlertDetails(self, alert):
        alert_id = alert['name']
        alert_timestamp = alert['properties']['startTimeUtc']
        self.logger.debug(f"Retrieving details for alert {alert_id}")
        # Query the SecurityAlert table with the alert id from the alert details to get the detail of the Alert out of the alert details in the alert << dat irony...
        data = {
            "query": f"""
            SecurityAlert
            | where SystemAlertId == "{alert_id}" and StartTime > datetime_add('minute', -1, datetime('{alert_timestamp}')) and StartTime < datetime_add('minute', 1, datetime('{alert_timestamp}'))
            | where isnotnull(ExtendedProperties)
            | limit 1
            | extend ExtendedProperties = todynamic(ExtendedProperties)
            | extend analytics_rule_name = iff(isnotnull(ExtendedProperties['Analytic Rule Name']), ExtendedProperties['Analytic Rule Name'], '<NA>')
            | extend custom_details = iff(isnotnull(ExtendedProperties['Custom Details']), ExtendedProperties['Custom Details'], '<NA>')
            | extend query = iff(isnotnull(ExtendedProperties['Query']), ExtendedProperties['Query'], '<NA>')
            | sort by TimeGenerated desc
            | project analytics_rule_name, custom_details, query
            """
        }

        detail_found = self.queryLogAnalytics(data)
        if detail_found:
            results = detail_found['tables'][0]['results'][0]
            for column_name in results:
                if results[column_name] != '<NA>':
                    alert[column_name] = results[column_name]
            return alert
        else:
            self.logger.debug("Could not retrieve/find alert query from Azure Sentinel")
            return False

    def updateIncidentStatusToActive(self, incident_id):
        url = self.base_url + '/incidents/{}?api-version=2020-01-01'.format(incident_id)

        response = self.azureRequest("get", url)
        if response['success']:
            incident = response['json']
            if incident['properties']['status'] == "Active":
                self.logger.info("Incident {} is already marked as Active".format(incident_id))
                return True
            else:
                data = {
                    "etag": "\"{}\"".format(incident['etag']),
                    "properties": {
                        "title": incident['properties']['title'],
                        "status": "Active",
                        "severity": incident['properties']['severity'],
                    }
                }
                response = self.azureRequest("put", url, data)
                if response['success']:
                    self.logger.debug("Incident {} is now marked as Active".format(incident_id))
                    return True
                else:
                    self.logger.error('Failed to update incident %s', incident_id, exc_info=True)
                    return False
        else:
            self.logger.error('Failed to update incident %s', incident_id, exc_info=True)
            return False

    def closeIncident(self, incident_id, classification, classification_comment):
        url = self.base_url + '/incidents/{}?api-version=2020-01-01'.format(incident_id)

        response = self.azureRequest("get", url)
        if response['success']:
            result = response['json']
            if result['properties']['status'] == "Closed":
                self.logger.info("Incident {} is already closed".format(incident_id))
                return True
            else:
                data = {
                    "etag": "{}".format(result['etag']),
                    "properties": {
                        "title": "{}".format(result['properties']['title']),
                        "status": "Closed",
                        "severity": "{}".format(result['properties']['severity']),
                        "classification": classification,
                        "classificationComment": classification_comment
                    }
                }
                # Some classifications require a classificationReason. Currently there is only one option
                if classification == "TruePositive":
                    data['properties']['classificationReason'] = "SuspiciousActivity"
                elif classification == "FalsePositive":
                    data['properties']['classificationReason'] = "IncorrectAlertLogic"
                elif classification == "BenignPositive":
                    data['properties']['classificationReason'] = "SuspiciousButExpected"

                response = self.azureRequest("put", url, data)
                if response['success']:
                    self.logger.info('Incident %s successsfully closed', incident_id)
                    return True
        else:
            self.logger.error('Failed to close incident', exc_info=True)

    def getRule(self, uri):

        url = 'https://management.azure.com{}?api-version={}'.format(uri, "2020-01-01")

        response = self.azureRequest("get", url)
        if response['success']:
            return response['json']
        else:
            self.logger.error("Could not retrieve rule information from Azure Sentinel", exc_info=True)
            return False

    def getRelatedAlerts(self, incident_id):
        # Endpoint that definines the alerts of an incident
        url = self.base_url + '/incidents/' + incident_id + '/alerts?api-version=2021-04-01'

        response = self.azureRequest("post", url)
        if response['success']:
            result = response['json']
            if 'value' in result and len(result['value']) > 0:
                return result['value']
            else:
                self.logger.debug("Azure Sentinel provided no results for related alerts")
                return False
        else:
            self.logger.warning("Could not retrieve/find related alerts from Azure Sentinel")
            return False

    def getEntities(self, incident_id):
        # Endpoint that provides entity information
        url = self.base_url + '/incidents/' + incident_id + '/entities?api-version=2021-04-01'

        response = self.azureRequest("post", url)
        if response['success']:
            result = response['json']
            if 'entities' in result and len(result['entities']) > 0:
                return result['entities']
            else:
                self.logger.debug("Azure Sentinel provided no results for entities")
                return False
        else:
            self.logger.warning("Could not retrieve/find entity information from Azure Sentinel")
            return False

    def getFirstEventForAlert(self, alert):
        self.logger.debug("Retrieving first event for alert {}".format(alert['name']))
        # Strip the comment lines out
        alert_query = re.sub(r"\/\/ .*?\r\n", "", alert['query'], flags=re.MULTILINE)
        alert_start = alert['properties']['startTimeUtc']
        alert_end = alert['properties']['endTimeUtc']

        # Remove new lines as json does not like them in particular
        data = {
            "query": alert_query.replace('\r\n', ' ') + ' | limit 1',
            "timespan": '{}/{}'.format(alert_start, alert_end)
        }

        alert_events = self.queryLogAnalytics(data)
        if alert_events:
            # Return only the first event
            if len(alert_events['tables'][0]['results']) > 0:
                return alert_events['tables'][0]['results'][0]
            else:
                self.logger.info("Azure Sentinel provided no actual results")
                return False
        else:
            return False

    def queryLogAnalytics(self, data):
        # Endpoint that can query log analytics
        url = 'https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.OperationalInsights/workspaces/{}/query'.format(self.subscription_id, self.resource_group, self.workspace) + '?api-version={}'.format("2017-10-01")
        self.logger.debug("Querying Log Analytics {} with data:\n{}".format(url, json.dumps(data, indent=4)))

        response = self.azureRequest("post", url, data)
        if response['success']:
            result = response['json']
            if 'tables' in result and len(result['tables']) > 0:
                self.logger.debug("Received the following raw results from Azure Sentinel: {}".format(json.dumps(result, indent=4)))
                return self.beautifyQueryResults(result['tables'])
            else:
                self.logger.debug("Azure Sentinel provided no results for the query")
                return False
        else:
            self.logger.error("Could not perform query in Azure Sentinel")
            return False

    def beautifyQueryResults(self, results):
        # Parse the incoming tables to a proper dictionary structure
        parsed_result = {"tables": []}
        for table in results:
            table_data = {}
            table_data['name'] = table['name']
            table_data['results'] = []

            # Loop through every row matching the column name for the current row identifier (vc)
            for row in table['rows']:
                results = {}
                for vc, row_value in enumerate(row):
                    if isinstance(row_value, str) and (row_value.startswith('[') and row_value.endswith(']') or row_value.startswith('{') and row_value.endswith('}')):
                        row_value = row_value.replace('\\r\\n', '\n')
                        try: 
                            results[table['columns'][vc]['name']] = json.loads(row_value)
                        except json.decoder.JSONDecodeError:
                            self.logger.warning(f"Could not parse json for: {row_value}")
                            results[table['columns'][vc]['name']] = row_value
                        except Exception as e:
                            self.logger.error(f"An unhandled exception occurred")
                    else:
                        results[table['columns'][vc]['name']] = row_value
                table_data['results'].append(results)
            parsed_result['tables'].append(table_data)
        self.logger.debug("Parsed the following beautified results from the query: {}".format(json.dumps(parsed_result, indent=4)))
        return parsed_result
            
### Error Handling classes

class SentinelError(Exception):
    """Raised when there is generic error with Sentinel"""
    pass
class SentinelUnhandledReturnCode(Exception):
    """Raised when there is an unexpected return code with Sentinel"""
    pass