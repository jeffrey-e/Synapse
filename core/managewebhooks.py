#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os, sys
import logging
from core.automator import Automator
from core.webhookidentifier import Webhook

def manageWebhook(webhookData, cfg, automation_config, modules):
    """
        Filter webhooks received from TheHive and initiate actions like:
            - closing offense in QRadar
    """
    logger = logging.getLogger(__name__)
    logger.info('%s.ManageWebhook starts', __name__)

    report = dict()
    report_action = False
    
    webhook = Webhook(webhookData, cfg)    
    
    #loop through all configured sections and create a mapping for the endpoints
    for cfg_section in cfg.sections():
        #Skip non module config
        if cfg_section in ['api', 'Automation']:
            continue
        automation_enabled = cfg.getboolean(cfg_section, 'automation_enabled', fallback=False)
        if automation_enabled:
            logger.info("Enabling automation for {}".format(cfg_section))

            try:
                #Load the Automation class from the module to initialise it
                automations = modules['automation'][cfg_section].Automation(webhook, cfg)
            except KeyError as e:
                logger.warning("Automation module not found: {}".format(cfg_section), exc_info=True)
                report['success'] = False
                return report

            #Run the function for the task and return the results
            report_action = automations.parse_hooks()

    if cfg.getboolean('Automation', 'enabled'):
         logger.info('Enabling Use Case Automation')
         uc_automation = Automator(webhook, cfg, automation_config, modules)
         report_action = uc_automation.check_automation()

    #Check if an action is performed for the webhook
    if report_action:
        report['action'] = report_action
        report['success'] = True
    else:
        report['success'] = False
    
    #return the report
    return report

if __name__ == '__main__':
    print('Please run from API only')
