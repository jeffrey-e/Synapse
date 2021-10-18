import logging
import re
from core.modules import Main
from datetime import datetime
from modules.TheHive.connector import TheHiveConnector
from modules.TheHive.automator import Automators as TheHiveAutomators
from thehive4py.models import CaseTask, Alert
from jinja2 import Template, Environment, meta
import socket

class GetOutOfLoop( Exception ):
    pass

class Automators(Main):
    def __init__(self, cfg, use_case_config):
        self.logger = logging.getLogger(__name__)
        self.logger.info('Initiating Network Automators')

        self.cfg = cfg
        self.use_case_config = use_case_config
        self.TheHiveConnector = TheHiveConnector(cfg)
        self.TheHiveAutomators = TheHiveAutomators(cfg, use_case_config)

    def nslookup(self, action_config, webhook):
        #Only continue if the right webhook is triggered
        if webhook.isNewAlert():
            pass
        else:
            return False
        
        #Define variables and actions based on certain webhook types
        #Alerts
        self.alert_id = webhook.data['object']['id']
        self.alert_description = webhook.data['object']['description']
        self.supported_query_type = 'enrichment_queries'
        if self.supported_query_type in action_config:
            self.query_config = action_config[self.supported_query_type]

        self.query_variables = {}
        self.query_variables['input'] = {}
        self.enriched = False

        #Prepare search queries for searches
        for query_name, query_config in self.query_config.items():
            try:
                self.logger.info('Found the following query: %s' % (query_name))
                self.query_variables[query_name] = {}
                self.logger.info("variables in the query: {}".format(query_config['query']))
                #Render query
                try:
                    #Prepare the template
                    self.template = Template(query_config['query'])

                    #Find variables in the template
                    self.template_env = Environment()
                    self.template_parsed = self.template_env.parse(query_config['query'])
                    #Grab all the variales from the template and try to find them in the description
                    self.template_vars = meta.find_undeclared_variables(self.template_parsed)
                    self.logger.info("Found the following variables in query: {}".format(self.template_vars))
                    
                    for template_var in self.template_vars:
                        
                        self.logger.debug("Looking up variable required for template: {}".format(template_var))
                        #Replace the underscore from the variable name to a white space as this is used in the description table
                        self.template_var_with_ws = template_var.replace("_", " ")
                        self.alert_data = self.TheHiveConnector.getAlert(self.alert_id)
                        self.logger.debug('output for get_alert: {}'.format(self.alert_data))
                        
                        self.query_variables['input'][template_var] = self.TheHiveAutomators.fetchValueFromMDTable(self.alert_data['description'],self.template_var_with_ws)
                    self.logger.info("Replaced variables: {}".format(self.query_variables['input']['Offense_Source']))
                    try:
                        self.enrichment_result=socket.gethostbyaddr(str(self.query_variables['input']['Offense_Source']))
                    except Exception as e:
                        self.logger.warning("Could not run socket.gethostbyaddr", exc_info=True)
                        self.enrichment_result="No results found"
                    self.logger.info("output: {}".format(self.enrichment_result))

                    #Add results to description
                    try:
                        if self.TheHiveAutomators.fetchValueFromMDTable(webhook,query_name) != self.enrichment_result:
                            self.regex_end_of_table = ' \|\\n\\n\\n'
                            self.end_of_table = ' |\n\n\n'
                            self.replacement_description = '|\n | **%s**  | %s %s' % (query_name, self.enrichment_result, self.end_of_table)
                            self.alert_description = self.TheHiveConnector.getAlert(self.alert_id)['description']
                            self.alert_description=re.sub(self.regex_end_of_table, self.replacement_description, self.alert_description)
                            self.enriched = True
                    except Exception as e:
                        self.logger.warning("Could not add results from the query to the description. Error: {}".format(e))
                        raise GetOutOfLoop
                except Exception as e:
                    self.logger.warning("Could not render query due to missing variables", exc_info=True)
                    raise GetOutOfLoop
            except GetOutOfLoop:
                pass

            # #Only enrichment queries need to update the alert out of the loop. The search queries will create a task within the loop
            if self.enriched:
                #Update Alert with the new description field
                self.updated_alert = Alert
                self.updated_alert.description = self.alert_description
                self.TheHiveConnector.updateAlert(self.alert_id, self.updated_alert, ["description"])
                self.logger.info("Alert was updated successfully")
            return True