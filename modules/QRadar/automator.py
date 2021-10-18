import logging
import re
from core.modules import Main
from datetime import datetime
from modules.TheHive.connector import TheHiveConnector
from modules.TheHive.automator import Automators as TheHiveAutomators
from modules.QRadar.connector import QRadarConnector
from thehive4py.models import CaseTask, Alert
from jinja2 import Template, Environment, meta

class GetOutOfLoop(Exception):
    pass

class Automators(Main):
    def __init__(self, cfg, use_case_config):
        self.logger = logging.getLogger(__name__)
        self.logger.info('Initiating QRadar Automators')

        self.cfg = cfg
        self.use_case_config = use_case_config
        self.TheHiveConnector = TheHiveConnector(cfg)
        self.TheHiveAutomators = TheHiveAutomators(cfg, use_case_config)
        self.QRadarConnector = QRadarConnector(cfg)

    def search(self, action_config, webhook):
        # Only continue if the right webhook is triggered
        self.logger.debug("action_config:{}".format(action_config))
        if webhook.isImportedAlert():
            pass
        else:
            return False

        # Define variables and actions based on certain webhook types
        self.case_id = webhook.data['object']['case']

        self.logger.debug(self.case_id)

        self.enriched = False
        for query_name, query_config in action_config.items():
            try:
                self.logger.debug('Found the following query: {}'.format(query_config['query']))
                self.query_variables = {}
                self.query_variables['input'] = {}

                # Render query
                try:
                    # Prepare the template
                    self.template = Template(query_config['query'])

                    # Find variables in the template
                    self.template_env = Environment()
                    self.template_parsed = self.template_env.parse(query_config['query'])
                    # Grab all the variales from the template and try to find them in the description
                    self.template_vars = meta.find_undeclared_variables(self.template_parsed)
                    self.logger.debug("Found the following variables in query: {}".format(self.template_vars))

                    for template_var in self.template_vars:

                        # Skip dynamically generated Stop_time variable
                        if template_var == "Stop_Time":
                            continue

                        self.logger.debug("Looking up variable required for template: {}".format(template_var))
                        # Replace the underscore from the variable name to a white space as this is used in the description table
                        self.template_var_with_ws = template_var.replace("_", " ")
                        self.case_data = self.TheHiveConnector.getCase(self.case_id)
                        self.logger.debug('output for get_case: {}'.format(self.case_data))
                        
                        self.query_variables['input'][template_var] = self.TheHiveAutomators.fetchValueFromMDTable(self.case_data['description'],self.template_var_with_ws)

                        if 'Start_Time' not in self.query_variables['input']:
                            self.logger.warning("Could not find Start Time value required to build the search")

                        # Parse times required for the query (with or without offset)
                        if template_var == "Start_Time":
                            self.logger.debug("Found Start Time: %s" % self.query_variables['input']['Start_Time'])
                            if 'start_time_offset' in query_config:
                                self.query_variables['input']['Start_Time'] = self.parseTimeOffset(self.query_variables['input']['Start_Time'], self.cfg.get('Automation', 'event_start_time_format'), query_config['start_time_offset'], self.cfg.get('QRadar', 'time_format'))
                            else:
                                self.query_variables['input']['Start_Time'] = self.query_variables['input']['Start_Time']

                            if 'stop_time_offset' in query_config:
                                self.query_variables['input']['Stop_Time'] = self.parseTimeOffset(self.query_variables['input']['Start_Time'], self.cfg.get('Automation', 'event_start_time_format'), query_config['stop_time_offset'], self.cfg.get('QRadar', 'time_format'))
                            else:
                                self.query_variables['input']['Stop_Time'] = datetime.now().strftime(self.cfg.get('Automation', 'event_start_time_format'))

                    self.rendered_query = self.template.render(self.query_variables['input'])
                    self.logger.debug("Rendered the following query: %s" % self.rendered_query)
                except Exception as e:
                    self.logger.warning("Could not render query due to missing variables", exc_info=True)
                    continue


                # Perform search queries
                try:
                    self.rendered_query_result = self.QRadarConnector.aqlSearch(self.rendered_query)
                    # Check results
                    self.logger.debug('The search result returned the following information: \n %s' % self.rendered_query_result)
                except Exception as e:
                    self.logger.warning("Could not perform query", exc_info=True)
                    continue

                try:
                    if query_config['create_thehive_task']:
                        self.logger.debug("create task is enabled")
                        # Task name
                        self.uc_task_title = query_config['thehive_task_title']
                        self.uc_task_description = "The following information is found. Investigate the results and act accordingly:\n\n\n\n"

                        # create a table header
                        self.table_header = "|"
                        self.rows = "|"
                        if len(self.rendered_query_result['events']) != 0:
                            for key in self.rendered_query_result['events'][0].keys():
                                self.table_header = self.table_header + " %s |" % key
                                self.rows = self.rows + "---|"
                            self.table_header = self.table_header + "\n" + self.rows + "\n"
                            self.uc_task_description = self.uc_task_description + self.table_header

                            # Create the data table for the results
                            for event in self.rendered_query_result['events']:
                                self.table_data_row = "|"
                                for field_key, field_value in event.items():
                                    # Escape pipe signs
                                    if field_value:
                                        field_value = field_value.replace("|", "&#124;")
                                    # Use &nbsp; to create some additional spacing
                                    self.table_data_row = self.table_data_row + " %s &nbsp;|" % field_value
                                self.table_data_row = self.table_data_row + "\n"
                                self.uc_task_description = self.uc_task_description + self.table_data_row
                        else:
                            self.uc_task_description = self.uc_task_description + "No results \n"

                        # Add the case task
                        self.uc_task = self.TheHiveAutomators.craftUcTask(self.uc_task_title, self.uc_task_description)
                        self.TheHiveConnector.createTask(self.case_id, self.uc_task)
                except Exception as e:
                    self.logger.debug(e)
                    pass
                try:
                    if query_config['create_ioc']:
                        self.logger.debug("create IOC is enabled")
                        self.comment="offense enrichment"
                        #static tags list
                        self.tags=['synapse']
                        #want to add SECID of the rule as well in the tag
                        rule_secid=[x for x in webhook.data['object']['tags'] if x.startswith('SEC')]
                        self.tags.extend(rule_secid)

                        self.uc_ioc_type = query_config['ioc_type']
                        if len(self.rendered_query_result['events']) != 0:
                            for event in self.rendered_query_result['events']:
                                for field_key, field_value in event.items():
                                    self.TheHiveConnector.addObservable(self.case_id, self.uc_ioc_type, list(field_value.split(",")), self.tags, self.comment)
                except Exception as e:
                    self.logger.debug(e)
                    pass

            except Exception as e:
                self.logger.debug('Could not process the following query: {}\n{}'.format(query_config,e))
                continue

        # Return True when succesful
        return True

    def enrichAlert(self, action_config, webhook):
        # Only continue if the right webhook is triggered
        if webhook.isNewAlert():
            pass
        else:
            return False

        # Define variables and actions based on certain webhook types
        # Alerts
        self.alert_id = webhook.data['object']['id']
        self.alert_description = webhook.data['object']['description']

        self.query_variables = {}
        self.query_variables['input'] = {}
        self.enriched = False
        # Prepare search queries for searches
        for query_name, query_config in action_config.items():
            try:
                self.logger.info('Found the following query: %s' % (query_name))
                self.query_variables[query_name] = {}

                # Render query
                try:
                    # Prepare the template
                    self.template = Template(query_config['query'])

                    # Find variables in the template
                    self.template_env = Environment()
                    self.template_parsed = self.template_env.parse(query_config['query'])
                    # Grab all the variales from the template and try to find them in the description
                    self.template_vars = meta.find_undeclared_variables(self.template_parsed)
                    self.logger.debug("Found the following variables in query: {}".format(self.template_vars))

                    for template_var in self.template_vars:

                        # Skip dynamically generated Stop_time variable
                        if template_var == "Stop_Time":
                            continue

                        self.logger.debug("Looking up variable required for template: {}".format(template_var))
                        # Replace the underscore from the variable name to a white space as this is used in the description table
                        self.template_var_with_ws = template_var.replace("_", " ")
                        self.alert_data = self.TheHiveConnector.getAlert(self.alert_id)
                        self.logger.debug('output for get_alert: {}'.format(self.alert_data))
                        
                        self.query_variables['input'][template_var] = self.TheHiveAutomators.fetchValueFromMDTable(self.alert_data['description'],self.template_var_with_ws)

                        # Parse times required for the query (with or without offset)
                        if template_var == "Start_Time":
                            self.logger.debug("Found Start Time: %s" % self.query_variables['input']['Start_Time'])
                            if 'start_time_offset' in query_config:
                                self.query_variables['input']['Start_Time'] = self.parseTimeOffset(self.query_variables['input']['Start_Time'], self.cfg.get('Automation', 'event_start_time_format'), query_config['start_time_offset'], self.cfg.get('QRadar', 'time_format'))
                            else:
                                self.query_variables['input']['Start_Time'] = self.query_variables['input']['Start_Time']

                            if 'stop_time_offset' in query_config:
                                self.query_variables['input']['Stop_Time'] = self.parseTimeOffset(self.query_variables['input']['Start_Time'], self.cfg.get('Automation', 'event_start_time_format'), query_config['stop_time_offset'], self.cfg.get('QRadar', 'time_format'))
                            else:
                                self.query_variables['input']['Stop_Time'] = datetime.now().strftime(self.cfg.get('Automation', 'event_start_time_format'))

                    if not self.query_variables['input']['Start_Time']:
                        self.logger.warning("Could not find Start Time value ")
                        raise GetOutOfLoop

                    self.query_variables[query_name]['query'] = self.template.render(self.query_variables['input'])
                    self.logger.debug("Rendered the following query: %s" % self.query_variables[query_name]['query'])
                except Exception as e:
                    self.logger.warning("Could not render query due to missing variables", exc_info=True)
                    raise GetOutOfLoop

                # Perform search queries
                try:
                    self.query_variables[query_name]['result'] = self.QRadarConnector.aqlSearch(self.query_variables[query_name]['query'])
                except Exception as e:
                    self.logger.warning("Could not perform query", exc_info=True)
                    raise GetOutOfLoop

                # Check results
                self.logger.debug('The search result returned the following information: \n %s' % self.query_variables[query_name]['result'])

                # making enrichment results presentable
                clean_enrichment_results = self.TheHiveAutomators.make_it_presentable(self.query_variables[query_name]['result']['events'][0]['enrichment_result'])

                # Add results to description
                success = self.enrichAlertDescription(self.alert_data['description'], query_name, self.query_variables[query_name]['result']['events'][0]['enrichment_result'])
                if not success:
                    self.logger.warning("Could not add results from the query to the description. Error: {}".format(e))
                    raise GetOutOfLoop

            except GetOutOfLoop:
                pass
        return True
