#!/usr/bin/env python3
# -*- coding: utf8 -*-

# load python modules
import os
import sys
import logging
import logging.handlers
import pickle
import time
import json
from flask import Flask, request, jsonify
from collections import namedtuple

# Load custom modules
from core.functions import getConf, loadAutomationConfiguration

# Import scheduler
from core.scheduler import EventScheduler, Event

app_dir = os.path.dirname(os.path.abspath(__file__))
cfg = getConf()

if cfg.getboolean("Automation", 'log_webhooks', fallback=False):
    # create logger
    webhook_logger = logging.getLogger("webhooks")
    webhook_logger.setLevel(logging.getLevelName("INFO"))
    # log format as: 2013-03-08 11:37:31,411 : : WARNING :: Testing foo bar
    webhook_formatter = logging.Formatter('%(asctime)s\n%(message)s')
    # handler writes into, limited to 1Mo in append mode
    if not cfg.getboolean('api', 'dockerized'):
        log_path = cfg.get('api', 'log_path', fallback=app_dir + "/logs")
        if not os.path.exists(log_path):
            # create logs directory if does no exist (typically at first start)
            os.makedirs(log_path)
        pathLog = log_path + '/synapse_received_webhooks.log'
        webhook_file_handler = logging.handlers.RotatingFileHandler(pathLog, 'a', 10000000, 10)
        # using the format defined earlier
        webhook_file_handler.setFormatter(webhook_formatter)
        # Adding the file handler
        webhook_logger.addHandler(webhook_file_handler)

# create logger
logger = logging.getLogger()
logger.setLevel(logging.getLevelName(cfg.get('api', 'log_level')))
# log format as: 2013-03-08 11:37:31,411 : : WARNING :: Testing foo
formatter = logging.Formatter('%(asctime)s :: %(process)d ::  %(name)s :: %(levelname)s :: %(message)s')
# handler writes into, limited to 1Mo in append mode
if not cfg.getboolean('api', 'dockerized'):
    log_path = cfg.get('api', 'log_path', fallback=app_dir + "/logs")
    if not os.path.exists(log_path):
        # create logs directory if does no exist (typically at first start)
        os.makedirs(log_path)
    pathLog = log_path + '/synapse.log'
    file_handler = logging.handlers.RotatingFileHandler(pathLog, 'a', 10000000, 10)
    # using the format defined earlier
    file_handler.setFormatter(formatter)
    # Adding the file handler
    logger.addHandler(file_handler)
else:
    # Logging to stdout
    out_hdlr = logging.StreamHandler(sys.stdout)
    out_hdlr.setFormatter(formatter)
    logger.addHandler(out_hdlr)

from core.managewebhooks import manageWebhook

# Load automation config
automation_config = loadAutomationConfiguration(cfg.get('Automation', 'automation_config_dir', fallback=None))
automation_list = []
for a_id in automation_config['automation_ids']:
    automation_list.append(a_id)
logger.info("Loaded the following automation identifiers: {}".format(automation_list))

# Initiate modules dict
modules = {}

from core.loader import moduleLoader
# Import automator modules
modules['automators'] = moduleLoader("automator")
# Import automation modules
modules['automation'] = moduleLoader("automation")
# Import integration modules
modules['integration'] = moduleLoader("integration")

# Load scheduler
cfg._scheduler = {}
cfg._scheduler['_object'] = EventScheduler("queue.pkl", cfg, automation_config, modules)

# loop through all configured sections and create a mapping for the enabled endpoints
enabled_integration_modules = {}
for cfg_section in cfg.sections():
    # Skip non module config
    if cfg_section in ['api', 'Automation']:
        continue
    endpoint = cfg.get(cfg_section, 'synapse_endpoint', fallback=False)
    if endpoint and cfg.getboolean(cfg_section, 'enabled'):
        logger.info("Enabling integration for {}: {}".format(cfg_section, endpoint))
        enabled_integration_modules[endpoint] = cfg_section

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

@app.before_first_request
def initialize():
    logger = logging.getLogger(__name__)

@app.route('/webhook', methods=['POST'])
def listenWebhook():
    if request.is_json:
        try:
            webhook = request.get_json()
            logger.debug("Webhook: %s" % json.dumps(webhook, indent=4))
            if cfg.getboolean("Automation", 'log_webhooks', fallback=False):
                webhook_logger.info(json.dumps(webhook, indent=4))
            workflowReport = manageWebhook(webhook, cfg, automation_config, modules)
            if workflowReport['success']:
                return jsonify(workflowReport), 200
            else:
                return jsonify(workflowReport), 500
        except Exception as e:
            logger.error('Failed to listen or action webhook: %s' % e, exc_info=True)
            return jsonify({'success': False}), 500
        logger.warning('Something went wrong for the incoming webhook...: {}'.format(json.dumps(webhook, indent=4)))
        return "ERROR: Webhook gave an error", 500

    else:
        return jsonify({'success': False, 'message': 'Not JSON'}), 400

# Use a dynamic route to receive integration based request and send them to the appropriate module found through the configuration
@app.route('/integration/<integration>', methods=['GET', 'POST', 'PUT'])
def endpoint(integration):
    try:
        # Use the enabled_integration_modules to verify if an integration is enabled, otherwise give a key error
        integration = modules['integration'][enabled_integration_modules[integration]].Integration()
        response = integration.validateRequest(request)
        return response
    except KeyError as e:
        logger.warning('Integration module not found or disabled: {}'.format(integration))
        return "ERROR: Integration module not found or disabled", 404
    logger.warning('Something went wrong...: {}'.format(integration))
    return "ERROR: Integration module gave an error", 500

@app.route('/automation_queue', methods=['GET', 'POST'])
def getQueueInformation():
    queue_info = {}
    QueueLog = namedtuple('Log', ['time', 'priority', 'action', 'argument'])
    if request.method in ["GET", "POST"]:
        queue_info['monotonic_time'] = time.monotonic()
        queue_info['memory_queue_running'] = cfg._scheduler['_object'].is_running()
        queue_info['memory_queue_length'] = len(cfg._scheduler['_object'].queue)
    if request.method == "POST" and request.is_json:
        try:
            queue_info_request = request.get_json()
            if queue_info_request['type'] in ["all", "memory"]:
                queue_info['memory_queue'] = []
                queue_content = cfg._scheduler['_object'].queue
                for queue_item in queue_content:
                    # Use argument[0] to exclude webhook object in the log as it is a non serializable class
                    queue_info['memory_queue'].append(QueueLog(queue_item.time, queue_item.priority, queue_item.action, queue_item.argument[0])._asdict())
            if queue_info_request['type'] in ["all", "persistent"]:
                path = cfg._scheduler['_object'].filepaths["q_path"]
                persistent_queue_content = cfg._scheduler['_object'].get_heap(path)
                queue_info['persistent_queue'] = []
                for persistent_queue_item in persistent_queue_content:
                    queue_info['persistent_queue'].append(QueueLog(persistent_queue_item.time, persistent_queue_item.priority, persistent_queue_item.action, persistent_queue_item.argument[0])._asdict())
        except Exception as e:
            logger.error('Failed to listen or action webhook: %s' % e, exc_info=True)
            return jsonify({'success': False}), 500
    else:
        return jsonify({'success': False}), 405
    return jsonify(queue_info), 200

@app.route('/version', methods=['GET'])
def getSynapseVersion():
    return jsonify({'version': '2.0.0'}), 200

if __name__ == '__main__':
    app.run(debug=cfg.getboolean('api', 'debug_mode'),
            host=cfg.get('api', 'host'),
            port=cfg.get('api', 'port'),
            threaded=cfg.get('api', 'threaded')
            )
