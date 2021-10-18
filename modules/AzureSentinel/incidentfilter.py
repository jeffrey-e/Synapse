import logging
import re
from core.functions import readYamlFile, typeCheck

class IncidentFilter:
    def __init__(self, cfg):
        self.cfg = cfg
        self.inclusion_config = readYamlFile(self.cfg.get('AzureSentinel', 'inclusion_config'))['inclusion_config']
        self.exclusion_config = readYamlFile(self.cfg.get('AzureSentinel', 'exclusion_config'))['exclusion_config']
        self.logger = logging.getLogger(__name__)

    def filterIncident(self, incident):
            """
            Returns True if the incident passes the filters and False if it is filtered out.
            """
            filter_log = ''
            self.logger.info(f'Starting filter for incident {incident["properties"]["incidentNumber"]}')
            # Run inclusion logic
            inclusion_match, filter_log = self.checkFilter(incident, filter_log, mode='inclusion')
            if inclusion_match is False:
                return False, filter_log
            # Run exclusion logic
            exclusion_match, filter_log = self.checkFilter(incident, filter_log, mode='exclusion')
            if exclusion_match:
                return False, filter_log
            # Add remaining incidents to incidents variable
            self.logger.debug(f'Incident {incident["properties"]["incidentNumber"]} passed both filters.')
            return True, filter_log

    def checkFilter(self, incident, filter_log, mode='inclusion'):
        """
        Returns True if the incident passes the inclusion list, False if it is filtered out.
        """
        if mode == 'inclusion':
            config = self.inclusion_config
        elif mode == 'exclusion':
            config = self.exclusion_config
        else:
            raise ValueError('Expected mode to be either "inclusion" or "exclusion"')
        for filter_config_dict in config:
            filter_config_name = list(filter_config_dict.keys())[0]
            filter_config = filter_config_dict[filter_config_name]
            # Create a dict containing filter function and the number of args they require
            filters = {
                'product': [self.productFilter, 3],
                'severity': [self.severityFilter, 2],
                'title': [self.stringFilter, 2],
                'entities': [self.entityFilter, 3],
                'custom_details': [self.customDetailsFilter, 2]
            }
            matched_filters = self.checkFilters(filters, filter_config, incident, mode)
            if matched_filters is True:
                if mode == 'inclusion':
                    message = f'Incident {incident["properties"]["incidentNumber"]} is included in {filter_config_name}, passing through filter.'
                else:
                    message = f'Incident {incident["properties"]["incidentNumber"]} is excluded by {filter_config_name}, filtering out incident.'
                self.logger.debug(message)
                filter_log += f'{message}\n'
                return True, filter_log
            else:
                continue
        message = f'Incident {incident["properties"]["incidentNumber"]} does not match any {mode} filter.'
        self.logger.debug(message)
        filter_log += f'{message}\n'
        return False, filter_log

    def checkFilters(self, filters, filter_config, incident, mode):
        for filter in filters:
            if filter in filter_config:
                filter_func = filters[filter][0]
                filter_n_args = filters[filter][1]
                filter_match = False
                if filter_n_args == 2:
                    filter_match = filter_func(filter_config, incident)
                elif filter_n_args == 3:
                    filter_match = filter_func(filter_config, incident, mode)
                # If this incident does not match this part of the inclusion, fail immediately.
                if filter_match is False:
                    return False
        return True

    def productFilter(self, filter_config, incident, mode):
        return self.checkProductFilter(filter_config['product'], incident['properties']['additionalData']['alertProductNames'], mode=mode)
        
    def checkProductFilter(self, filter_config, alertProductNames, mode='inclusion'):
        partial_results = []
        typeCheck(alertProductNames, list, 'alertProductNames')
        if isinstance(filter_config, list):
            if mode == 'exclusion' and (len(filter_config) is not len(alertProductNames)):
                self.logger.debug(f'{filter_config} and {alertProductNames} differ in length and does not match exclusion.')
                return False
            for alertProduct in alertProductNames:
                # Do we want to match in lower case?
                if alertProduct in filter_config:
                    partial_results.append(True)
                else:
                    partial_results.append(False)
        elif isinstance(filter_config, str):
            if mode == 'exclusion' and isinstance(alertProductNames, list) and len(alertProductNames) > 1:
                self.logger.debug(f'Exclusion {filter_config} is a string and does not match a list for exclusion.')
                return False
            for alertProduct in alertProductNames:
                if alertProduct == filter_config:
                    partial_results.append(True)
                else:
                    partial_results.append(False)

        if mode == 'inclusion':
            if True not in partial_results:
                self.logger.debug(f'{alertProductNames} did not match any inclusions.')
                return False
        elif mode == 'exclusion':
            if False in partial_results:
                self.logger.debug(f'{alertProductNames} did not match any exclusions.')
                return False
        self.logger.debug(f'{alertProductNames} matched {filter_config}.')
        return True

    def severityFilter(self, filter_config, incident):
        return self.checkSeverityFilter(filter_config['severity'], incident['properties']['severity'])

    def checkSeverityFilter(self, filter_config, severity):
        typeCheck(severity, str, 'Severity')
        typeCheck(filter_config, [list, str], 'filter_config')
        if isinstance(filter_config, list):
            # Do we want to match in lower case?
            if severity in filter_config:
                self.logger.debug(f'{severity} is contained in {filter_config}.')
                return True
        elif isinstance(filter_config, str):
            if severity == filter_config:
                self.logger.debug(f'{severity} matches {filter_config}.')
                return True
        self.logger.debug(f'{severity} did not match with {filter_config}.')
        return False

    def stringFilter(self, filter_config, incident):
        if 'title' in filter_config:
            if (self.checkProductFilter(['Azure Sentinel'], incident['properties']['additionalData']['alertProductNames']) is True and
                'analytics_rule_names' in incident):
                for rule_name in incident['analytics_rule_names']:
                    title_match = self.checkStringFilter(filter_config['title'], rule_name)
                    if title_match == True:
                        return True
                return False
            else:
                return self.checkStringFilter(filter_config['title'], incident['properties']['title'])

    def checkStringFilter(self, filter_config, string):
        typeCheck(string, str, 'String')
        typeCheck(filter_config, [str, list], 'filter_config')
        if isinstance(filter_config, str):
            if filter_config.lower() in string.lower():
                self.logger.debug(f'{string} matched {filter_config}.')
                return True
        if isinstance(filter_config, list):
            for item in filter_config:
                if isinstance(item, str):
                    if item.lower() in string.lower():
                        self.logger.debug(f'{string} matched {item}.')
                        return True
                if isinstance(item, dict):
                    if 'regex' in item:
                        match = re.search(item['regex'], string)
                        if match:
                            self.logger.debug(f'{string} matched regex {item["regex"]}.')
                            return True
                    elif 'contains_all' in item:
                        partial_results = []
                        for filter_config in item['contains_all']:
                            partial_results.append(filter_config.lower() in string.lower())
                        if False not in partial_results:
                            self.logger.debug(f'{string} matched all substrings in {item["contains_all"]}.')
                            return True
        self.logger.debug(f'{string} did not match any filter_config.')
        return False

    def entityFilter(self, filter_config, incident, mode):
        if 'entities' in incident:
            return self.checkEntityFilter(filter_config['entities'], incident['entities'], mode=mode)
        else:
            return False

    def checkEntityFilter(self, filter_config, entities, mode='inclusion'):
        # If the incident has no Entities, the filter cannot match and returns False.
        if entities is False:
            self.logger.debug('No entities found in incident')
            return False
        # checkEntityFilter will only accept lists of dictionaries as input.
        typeCheck(filter_config, list, f'{mode} filter')
        # Iterate through each inclusion dict found in the Entity inclusion list
        results = []
        for filter_config_dict in filter_config:
            # Retrieve the dict inside the dict
            filter_config_name = list(filter_config_dict.keys())[0]
            filter_config = filter_config_dict[filter_config_name]
            partial_results = []
            typeCheck(entities, [dict, list], 'Entities')
            if isinstance(entities, list):
                if mode == 'exclusion' and len(filter_config) > len(entities):
                    self.logger.debug(f'More Entities in {mode} filter than in incident. Exclusion cannot match.')
                    partial_results.append(False)
                for entity in entities:
                    partial_results.append(self.compareEntities(filter_config, entity))
            elif isinstance(entities, dict):
                if mode == 'exclusion' and len(filter_config) > 1:
                    self.logger.debug(f'More Entities in {mode} filter than in incident. Exclusion cannot match.')
                    partial_results.append(False)
                else:
                    partial_results.append(self.compareEntities(filter_config, entities))
            # If a matching Entity is found and mode is inclusion, return True.
            if True in partial_results:
                results.append(True)
            else:
                results.append(False)
            # If all entities match and mode is exclusion, return True.
        if ((mode == 'inclusion' and True in results) or
        (mode == 'exclusion' and False not in results)):
            self.logger.debug(f'Entity matched {mode} {filter_config_name}.')
            return True
        else:
            self.logger.debug(f'Entities did not match any {mode}s.')
            return False

    def compareEntities(self, filter_config, entity):
        typeCheck(filter_config, dict, 'filter_config')
        typeCheck(entity, dict, 'Entity')
        # Check if Entity types match
        if self.checkStringFilter(entity['kind'], filter_config['kind']):
            tertial_results = []
            # Iterate through fields defined in the filter
            for key in filter_config['properties']:
                # Check if field is present in the Entity
                if key in entity['properties']:
                    self.logger.debug(f'{key} was found in {entity["properties"]}.')
                    # The StringFilter is applied to the matching field in the entity.
                    tertial_results.append(self.checkStringFilter(filter_config['properties'][key], entity['properties'][key]))
                # If the key is not in the entity, it cannot match the filter.
                else:
                    self.logger.debug(f'{key} was not found in {entity["properties"]}.')
                    return False
            # If False is in tertial_results, there is no full match.
            if False in tertial_results:
                self.logger.debug('filter_config does not match Entity.')
                return False
            # If there is no False in tertial_results, there has been a full match.
            else:
                self.logger.debug('filter_config matches Entity.')
                return True
        # If Entity type does not match the inclusion it cannot match.
        else:
            self.logger.debug('filter_config does not match Entity.')
            return False

    def customDetailsFilter(self, filter_config, incident):
        if 'custom_details' not in incident:
            return False
        else:
            custom_detail_match = self.checkCustomDetailsFilter(filter_config['custom_details'], incident['custom_details'])
            return custom_detail_match

    def checkCustomDetailsFilter(self, filter_config, custom_details):
        """
        Incidents can contain many alerts, which can each contain many custom details. Which is
        why I've chosen to return True if the custom detail defined in the filter matches.
        """
        typeCheck(filter_config, dict, 'filter_config')
        typeCheck(custom_details, list, 'Custom Details')
        for detail in custom_details:
            for key in filter_config:
                if key in detail:
                    for item in detail[key]:
                        string_match = self.checkStringFilter(filter_config[key], item)
                        if string_match is True:
                            return True
        return False