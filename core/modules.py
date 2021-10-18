import logging
import re
import pytz
import threading
from distutils.util import strtobool
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from jinja2 import Template, Environment, meta

class Main():
    def __init__(self, cfg, use_case_config):
        self.logger = logging.getLogger(__name__)
        self.cfg = cfg
        self.scheduler = self.cfg._scheduler['_object']

    def schedule(self, task_config, arguments, days=0, hours=0, minutes=0, repeat=False):
        task = task_config['task'].split(".")
        module_name = task[0]
        function_name = task[1]

        self.logger.debug('Scheduling event for {}, {}, {}, {}, {}, {}, {}'.format(module_name, function_name, arguments, days, hours, minutes, repeat))
        self.scheduler.schedule_after_time(module_name, function_name, arguments, days, hours, minutes)
        
        if not self.scheduler.is_running():
            self.logger.info('Starting scheduler')
            scheduler_thread = threading.Thread(target=self.scheduler.run)
            scheduler_thread.daemon = True
            scheduler_thread.start()
            

    def checkScheduleOptions(self, task_config):
        run_immediately = False
        time_config = None
        # Verify if the task should be scheduled or not
        if 'schedule' in task_config:
            if 'run_immediately' in task_config['schedule']:
                if bool(strtobool(str(task_config['schedule']['run_immediately']))):
                    run_immediately = True

            # Schedule task
            time_config = {"minutes" : task_config['schedule'].get('minutes', 0),
                           "hours" : task_config['schedule'].get('hours', 0),
                           "days" : task_config['schedule'].get('days', 0),
                           "repeat" : task_config['schedule'].get('repeat', 0)}

            # Make a deepcopy to not affect the global action_config.
            task_config = deepcopy(task_config)
            # Remove scheduling option to avoid an infinite scheduling loop.
            del task_config['schedule']
        return (run_immediately, time_config, task_config)

    # Small timezone converter. Source: https://stackoverflow.com/questions/4563272/convert-a-python-utc-datetime-to-a-local-datetime-using-only-python-standard-lib
    def utc_to_local(self, utc_dt):
        return utc_dt.replace(tzinfo=timezone.utc).astimezone(tz=pytz.timezone('CET'))

    '''
    Can be used to extract values from the alert/case description in a webhook
    '''
    def fetchValueFromMDTable(self, in_data, variable):
        self.value_regex = '\|\s*\*\*%s\*\*\s*\|\s*(.*?)\s*\|' % variable

        try:
            # The tag should match this regex to find the value
            value = re.search(self.value_regex, in_data).group(1)
            self.logger.debug("Found value for template variable {}: {}".format(variable, value))
            value = self.make_it_original(value)
            self.logger.debug("Reverted the value for template variable to the original {}: {}".format(variable, value))
            return value
        except Exception as e:
            self.logger.warning("Could not find value for variable {}".format(variable))
            self.logger.debug("The following error has occurred: {}".format(e))
            return None
    '''
    replace the special chars like "|" with html code which ruin the alert decription markup
    https://stackoverflow.com/questions/17319940/how-to-escape-a-pipe-char-in-a-code-statement-in-a-markdown-table
    '''
    def make_it_presentable(self, in_data):
        clean_str= re.sub("\|","&#124;",in_data)
        # in case there is a unicode chars in the string
        clean_str= clean_str.encode('unicode_escape').decode('UTF-8')
        return clean_str
        
    '''
    for the search and enrichment queries you need the original field names from the alert decription
    '''
    def make_it_original(self, in_data):
        original_str= re.sub("&#124;","\|",in_data)
        return original_str

    def parseTimeOffset(self, time, input_format, offset, output_format):
        # Use input format when no output format is provided
        if output_format is None:
            output_format = input_format
        self.start_time_parsed = datetime.strptime(time, input_format)
        self.start_time_parsed = self.start_time_parsed - timedelta(minutes=offset)
        self.logger.debug("Time with offset: %s" % self.start_time_parsed.strftime(output_format))
        return self.start_time_parsed.strftime(output_format)

    def checkCustomerId(self):
        if 'internal' in self.use_cases[self.rule_id] and self.use_cases[self.rule_id]['internal']:
            self.logger.info("Rule %s is marked as internal" % self.rule_id)
            self.results = self.use_case_config['configuration']['internal_contact']
        elif 'debug' in self.use_cases[self.rule_id] and self.use_cases[self.rule_id]['debug']:
            self.logger.info("Using debug settings for rule %s" % self.rule_id)
            self.results = self.use_case_config['configuration']['debug_contact']
        else:
            self.results = self.MatchValueAgainstTags(self.tags, self.customers)

        return self.results

    def renderTemplate(self, body, tags, webhook, notification_type, **kwargs):
        self.logger.info('%s.renderTemplate starts', __name__)
        self.body = body
        self.rendered_template = ""
        self.stopsend = False
        self.customer_id = kwargs.get('customer_id', None)
        self.mail_settings = kwargs.get('mail_settings', None)

        # Retrieve variables from the mail template
        self.logger.info('Templating the following body: %s' % self.body)
        self.template = Template(self.body)

        # Find variables in the template
        self.template_env = Environment()
        self.template_parsed = self.template_env.parse(self.body)
        # Grab all the variales from the template and try to find them in the rendered_template
        self.template_vars = meta.find_undeclared_variables(self.template_parsed)
        self.logger.debug("Found the following variables in template: {}".format(self.template_vars))

        # Define the templating dict
        self.template_variables = {}

        for template_var in self.template_vars:
            self.logger.debug("Looking up variable required for template: {}".format(template_var))
            # Replace the underscore from the variable name to a white space as this is used in the rendered_template table
            self.template_var_with_ws = template_var.replace("_", " ")
            self.logger.debug("Variable name after replacing whitespaces: {}".format(self.template_var_with_ws))
            self.template_variables[template_var] = self.fetchValueFromMDTable(webhook, self.template_var_with_ws)
            # Parse the timestamp to a reasonable format
            if template_var == 'Start_Time':
                try:
                    self.logger.debug("Changing timestamp %s" % self.replacement_var)
                    timestamp = datetime.strptime(self.template_variables[template_var], self.cfg.get('Automation', 'event_start_time_format'))
                    # convert to local time
                    local_timestamp = self.utc_to_local(timestamp)
                    self.template_variables[template_var] = local_timestamp.strftime("%Y-%m-%d %H:%M:%S")
                    self.logger.debug("Changed timestamp to %s" % self.template_variables[template_var])
                except Exception as e:
                    self.logger.error("Could not change timestamp: %s" % template_var, exc_info=True)

        # Render the template
        self.body = self.template.render(self.template_variables)

        # loop through tags to see if there is a recipient present
        if self.customer_id and notification_type == 'email':
            self.logger.info('Found customer %s, retrieving recipient' % self.customer_id)
            self.rendered_template = 'mailto:%s\n' % self.customer_cfg.get(self.customer_id, 'recipient')
        if not self.customer_id and notification_type == 'email':
            self.logger.warning('Could not find customer in tags, using default template')
            self.rendered_template = 'mailto:{recipient}\n'
            self.stopsend = True

        if notification_type == "email":
            if 'header' in self.mail_settings:
                self.rendered_template += '%s \n\n' % self.mail_settings['header']

            # Add the body
            self.rendered_template += '%s \n' % self.body

            if 'footer' in self.mail_settings:
                self.rendered_template += '%s \n' % self.mail_settings['footer']

            if 'sender_name' in self.mail_settings:
                self.rendered_template += '%s' % self.mail_settings['sender_name']

        else:
            # Add the body
            self.rendered_template += '%s \n' % self.body

        return self.rendered_template

