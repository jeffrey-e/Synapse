import ipaddress
import logging
import re
from core.functions import getConf

class Main():
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.cfg = getConf()

    def tagExtractor(self, dict, field_names, extraction_regexes):
        self.logger.debug('%s.tagExtractor starts', __name__)
        self.matches = []
        for field_name in field_names:
            for extraction_regex in extraction_regexes:
                self.regex = re.compile(extraction_regex)
                self.logger.debug("offense: %s" % dict[field_name])
                self.matches.extend(self.regex.findall(str(dict[field_name])))
                self.matches = list(dict.fromkeys(self.matches))
        if len(self.matches) > 0:
            self.logger.debug("matches: %s" % self.matches)
            return self.matches
        else:
            return []

    def checkObservableTLP(self, artifacts):
        self.artifacts = []

        if self.cfg.get('Automation', 'tlp_modifiers', fallback=None):
            self.logger.debug(" TLP modifiers found. Checking for matches")
            for artifact in artifacts:
                for tlp, tlp_config in self.cfg.get('Automation', 'tlp_modifiers').items():

                    self.tlp_table = {
                        "white": 0,
                        "green": 1,
                        "amber": 2,
                        "red": 3
                    }

                    self.tlp_int = self.tlp_table[tlp]

                    for observable_type, observable_type_config in tlp_config.items():
                        if observable_type == 'ip' and artifact['dataType'] == 'ip':
                            for entry in observable_type_config:
                                # Initial values
                                self.match = False
                                observable_ip = ipaddress.ip_address(artifact['data'])

                                # Match ip with CIDR syntax
                                if entry[-3:] == "/32":
                                    self.tlp_list_entry = ipaddress.ip_address(entry[:-3])
                                    self.match = observable_ip == self.tlp_list_entry
                                # Match ip without CIDR syntax
                                elif "/" not in entry:
                                    self.tlp_list_entry = ipaddress.ip_address(entry)
                                    self.match = observable_ip == self.tlp_list_entry
                                # Capture actual network entries
                                else:
                                    self.tlp_list_entry = ipaddress.ip_network(entry, strict=False)
                                    self.match = observable_ip in self.tlp_list_entry

                                # If matched add it to new entries to use outside of the loop
                                if self.match:
                                    self.logger.debug("Observable {} has matched {} through {} of the TLP modifiers list. Adjusting TLP...".format(artifact['data'], tlp, entry))
                                    artifact['tlp'] = self.tlp_int
                        elif artifact['dataType'] == observable_type:
                            for extraction_regex in observable_type_config:
                                self.regex = re.compile(extraction_regex)
                                if self.regex.search(artifact['data']):
                                    self.logger.debug("Observable {} with type {} has matched {} through {} of the TLP modifiers list. Adjusting TLP...".format(artifact['data'], observable_type, tlp, extraction_regex))
                                    artifact['tlp'] = self.tlp_int

                # Set default TLP for artifact when no TLP tag is present
                if 'tlp' not in artifact:
                    artifact['tlp'] = self.cfg.get('Automation', 'default_observable_tlp')
                # Add artifact to an array again
                self.artifacts.append(artifact)

            return self.artifacts
        else:
            return artifacts

    def checkObservableExclusionList(self, artifacts):
        self.artifacts = []
        self.exclusions = self.cfg.get('Automation', 'observable_exclusions', fallback=None)
        if self.exclusions:
            self.logger.debug(" Observable exclusions found. Checking for matches")
            for artifact in artifacts:
                # Initial values
                self.match_found = False

                for observable_type, observable_type_config in self.exclusions.items():
                    if observable_type == 'ip' and artifact['dataType'] == 'ip':
                        for entry in observable_type_config:
                            observable_ip = ipaddress.ip_address(artifact['data'])

                            # Match ip with CIDR syntax
                            if entry[-3:] == "/32":
                                self.tlp_list_entry = ipaddress.ip_address(entry[:-3])
                                self.match = observable_ip == self.tlp_list_entry
                            # Match ip without CIDR syntax
                            elif "/" not in entry:
                                self.tlp_list_entry = ipaddress.ip_address(entry)
                                self.match = observable_ip == self.tlp_list_entry
                            # Capture actual network entries
                            else:
                                self.tlp_list_entry = ipaddress.ip_network(entry, strict=False)
                                self.match = observable_ip in self.tlp_list_entry
                            # Mark match found when ip matches
                            if self.match:
                                self.match_found = True
                                self.matched_on = entry

                    elif artifact['dataType'] == observable_type:
                        for extraction_regex in observable_type_config:
                            self.regex = re.compile(extraction_regex)
                            if self.regex.search(artifact['data']):
                                self.match_found = True
                                self.matched_on = extraction_regex
                if self.match_found:
                    self.logger.debug("Observable {} with type {} has matched through {} of the exclusion list. Ignoring observable...".format(artifact['data'], artifact['dataType'], self.matched_on))
                    continue
                # Add artifact to an array again
                self.artifacts.append(artifact)

            return self.artifacts
        else:
            return artifacts

    def checkIfInClosedCaseOrAlertMarkedAsRead(self, sourceref):
        query = dict()
        query['sourceRef'] = str(sourceref)
        self.logger.debug('Checking if third party ticket({}) is linked to a closed case'.format(sourceref))
        alert_results = self.TheHiveConnector.findAlert(query)
        if len(alert_results) > 0:
            alert_found = alert_results[0]
            if alert_found['status'] == 'Ignored':
                self.logger.info(f"{sourceref} is found in alert {alert_found['id']} that has been marked as read")
                return {"resolutionStatus": "Indeterminate", "summary": "Closed by Synapse with summary: Marked as Read within The Hive"}
            elif 'case' in alert_found:
                # Check if alert is present in closed case
                case_found = self.TheHiveConnector.getCase(alert_found['case'])
                if case_found['status'] == "Resolved":
                    if case_found['resolutionStatus'] != "Duplicated":
                        self.logger.info(f"{sourceref} was found in a closed case {case_found['id']}")
                        resolution_status = "N/A"
                        resolution_summary = "N/A"
                        # Return information required to sync with third party
                        if 'resolutionStatus' in case_found:
                            resolution_status = case_found['resolutionStatus']
                        if 'summary' in case_found:
                            resolution_summary = case_found['summary']
                        return {"resolutionStatus": resolution_status, "summary": resolution_summary}
                    else:
                        self.logger.info(f"{sourceref} was found in a duplicated case {case_found['id']}")
                        merged_case_found = self.getFinalMergedCase(case_found)
                        if merged_case_found['status'] == "Resolved":
                            if 'resolutionStatus' in merged_case_found:
                                resolution_status = merged_case_found['resolutionStatus']
                            if 'summary' in merged_case_found:
                                resolution_summary = merged_case_found['summary']
                            return {"resolutionStatus": resolution_status, "summary": resolution_summary}
        return False

    def getFinalMergedCase(self, duplicated_case, handled_cases=[]):
        # Match on duplicated cases
        if 'mergeInto' in duplicated_case:
            merged_into = duplicated_case['mergeInto']
            case_found = self.TheHiveConnector.getCase(merged_into)
            if 'resolutionStatus' in case_found:
                if case_found['resolutionStatus'] == "Duplicated" and merged_into not in handled_cases:
                    handled_cases.append(merged_into)
                    case_found = self.getFinalMergedCase(case_found, handled_cases)
        # Match on other cases
        else:
            # Add the duplicated_case when no further merges are found
            case_found = duplicated_case
        return case_found
