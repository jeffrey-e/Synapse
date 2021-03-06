import logging
import json
import requests
import re

from core.modules import Main

class Automators(Main):
    def __init__(self, cfg, use_case_config):
        self.logger = logging.getLogger(__name__)
        self.logger.info('Initiating Slack Automators')

        self.cfg = cfg
    
    def SendNotificationFromAlert(self, action_config, webhook):
        #Only continue if the right webhook is triggered
        if webhook.isImportedAlert():
            pass
        else:
            return False

        self.tags = webhook.data['object']['tags']
        self.title = action_config['title']

        if self.cfg.getboolean('Automation','enable_customer_list', fallback=False):
            self.customer_id = self.checkCustomerId()
            try:
                self.url = self.customer_cfg.get(self.customer_id, 'teams_url')
            except:
                self.logger.warning("Could not retrieve url for customer %s, using default" % self.customer_id)
        else:
            self.customer_id = None
            self.url = self.cfg.get('Teams', 'url')

        #Fallback for notification where no short_template is available
        if 'short_template' in action_config:
            template = action_config['short_template']
        else:
            template = action_config['long_template']

        self.notification_type = "teams"
        self.rendered_template = self.renderTemplate(template, self.tags, webhook, self.notification_type, customer_id=self.customer_id)
        
        if hasattr(self, 'url'):
            self.teams_data = {}
            self.teams_data['text'] = "***%s***</br><pre>%s</pre>" % (self.title, self.rendered_template)

            try:
                self.response = requests.post(self.url, data=json.dumps(self.teams_data), headers={'Content-Type': 'application/json'})
                if self.response.status_code not in [200, 201]:
                    self.logger.error("Something went wrong when posting to teams: %s" % self.response.raw.read())
            except Exception as e:
                self.logger.error("Could not post alert to teams", exc_info=True)