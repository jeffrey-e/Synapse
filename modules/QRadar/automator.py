
import logging
import re
from core.modules import Main
from datetime import datetime
from modules.TheHive.connector import TheHiveConnector
from modules.TheHive.automator import Automators as TheHiveAutomators
from modules.QRadar.connector import QRadarConnector
from thehive4py.models import CaseTask, Alert
from jinja2 import Template, Environment, meta

class GetOutOfLoop( Exception ):
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

    def checkSiem(self, action_config, webhook):
        #Only continue if the right webhook is triggered
        if webhook.isImportedAlert() or webhook.isNewAlert() or webhook.isQRadarAlertUpdateFollowTrue():
            pass
        else:
            return False
        
        #Define variables and actions based on certain webhook types
        #Alerts
        if webhook.isNewAlert() or webhook.isQRadarAlertUpdateFollowTrue():
            self.alert_id = webhook.data['object']['id']
            self.alert_description = webhook.data['object']['description']
            self.supported_query_type = 'enrichment_queries'

        #Cases
        elif webhook.isImportedAlert():
            self.case_id = webhook.data['object']['case']
            self.supported_query_type = 'search_queries'


        self.query_variables = {}
        self.query_variables['input'] = {}
        self.enriched = False
        #Prepare search queries for searches
        for query_name, query_config in action_config[self.supported_query_type].items():
            try:
                self.logger.info('Found the following query: %s' % (query_name))
                self.query_variables[query_name] = {}
                
                #Render query
                try:
                    #Prepare the template
                    self.template = Template(query_config['query'])

                    #Find variables in the template
                    self.template_env = Environment()
                    self.template_parsed = self.template_env.parse(query_config['query'])
                    #Grab all the variales from the template and try to find them in the description
                    self.template_vars = meta.find_undeclared_variables(self.template_parsed)
                    self.logger.debug("Found the following variables in query: {}".format(self.template_vars))

                    for template_var in self.template_vars:
                        
                        #Skip dynamically generated Stop_time variable
                        if template_var == "Stop_Time":
                            continue
                        
                        self.logger.debug("Looking up variable required for template: {}".format(template_var))
                        #Replace the underscore from the variable name to a white space as this is used in the description table
                        self.template_var_with_ws = template_var.replace("_", " ")
                        self.query_variables['input'][template_var] = self.TheHiveAutomators.fetchValueFromDescription(webhook,self.template_var_with_ws)
                        
                        #Parse times required for the query (with or without offset)
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
                
                #Perform search queries
                try:
                    self.query_variables[query_name]['result'] = self.QRadarConnector.aqlSearch(self.query_variables[query_name]['query'])
                except Exception as e:
                    self.logger.warning("Could not perform query", exc_info=True)
                    raise GetOutOfLoop
            
                #Check results
                self.logger.debug('The search result returned the following information: \n %s' % self.query_variables[query_name]['result'])
                    
                if self.supported_query_type == "search_queries":
                    #Task name
                    self.uc_task_title = query_config['task_title']
                
                    self.uc_task_description = "The following information is found. Investigate the results and act accordingly:\n\n\n\n"
                    
                    #create a table header
                    self.table_header = "|" 
                    self.rows = "|"
                    if len(self.query_variables[query_name]['result']['events']) != 0:
                        for key in self.query_variables[query_name]['result']['events'][0].keys():
                            self.table_header = self.table_header + " %s |" % key
                            self.rows = self.rows + "---|"
                        self.table_header = self.table_header + "\n" + self.rows + "\n"
                        self.uc_task_description = self.uc_task_description + self.table_header
                        
                        #Create the data table for the results
                        for event in self.query_variables[query_name]['result']['events']:
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
                        
                    
                    #Add the case task
                    self.uc_task = self.TheHiveAutomators.craftUcTask(self.uc_task_title, self.uc_task_description)
                    self.TheHiveConnector.createTask(self.case_id, self.uc_task)

                if self.supported_query_type == "enrichment_queries":

                    #Add results to description
                    try:
                        if self.TheHiveAutomators.fetchValueFromDescription(webhook,query_name) != self.query_variables[query_name]['result']['events'][0]['enrichment_result']:
                            self.regex_end_of_table = ' \|\\n\\n\\n'
                            self.end_of_table = ' |\n\n\n'
                            self.replacement_description = '|\n | **%s**  | %s %s' % (query_name, self.query_variables[query_name]['result']['events'][0]['enrichment_result'], self.end_of_table)
                            self.th_alert_description = self.TheHiveConnector.getAlert(self.alert_id)['description']
                            self.alert_description = re.sub(self.regex_end_of_table, self.replacement_description, self.th_alert_description)
                            self.enriched = True
                            #Update Alert with the new description field
                            self.updated_alert = Alert
                            self.updated_alert.description = self.alert_description
                            self.TheHiveConnector.updateAlert(self.alert_id, self.updated_alert, ["description"])
                    except Exception as e:
                        self.logger.warning("Could not add results from the query to the description. Error: {}".format(e))
                        raise GetOutOfLoop

            except GetOutOfLoop:
                pass
        return True