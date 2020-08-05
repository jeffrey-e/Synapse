#!/usr/bin/env python3
# -*- coding: utf8 -*-

#load python modules
import os
import sys
import logging, logging.handlers
from flask import Flask, request, jsonify

#Load custom modules
from core.functions import getConf, loadUseCases

app_dir = os.path.dirname(os.path.abspath(__file__))
cfg = getConf()

#create logger
logger = logging.getLogger()
logger.setLevel(logging.getLevelName(cfg.get('api', 'log_level')))
#log format as: 2013-03-08 11:37:31,411 : : WARNING :: Testing foo
formatter = logging.Formatter('%(asctime)s :: %(name)s :: %(levelname)s :: %(message)s')
#handler writes into, limited to 1Mo in append mode
if not cfg.getboolean('api', 'dockerized'):
    if not os.path.exists('logs'):
        #create logs directory if does no exist (typically at first start)
        os.makedirs('logs')
    pathLog = app_dir + '/logs/synapse.log'
    file_handler = logging.handlers.RotatingFileHandler(pathLog, 'a', 1000000, 1)
    #using the format defined earlier
    file_handler.setFormatter(formatter)
    #Adding the file handler
    logger.addHandler(file_handler)
else:
    #Logging to stdout
    out_hdlr = logging.StreamHandler(sys.stdout)
    out_hdlr.setFormatter(formatter)
    logger.addHandler(out_hdlr)

from modules.EWS.integration import validateRequest
from modules.QRadar.integration import validateRequest
from modules.ELK.integration import validateRequest
from core.managewebhooks import manageWebhook

#Load use cases
use_cases = loadUseCases()
use_case_list = []
for ucs in use_cases['use_cases']:
    use_case_list.append(ucs)
#use_case_list = ",".join(use_case_list)
logger.info("Loaded the following use cases: {}".format(use_case_list))

app = Flask(__name__)

@app.before_first_request
def initialize():
    logger = logging.getLogger(__name__)

@app.route('/webhook', methods=['POST'])
def listenWebhook():
    if request.is_json:
         try:
            webhook = request.get_json()
            logger.debug("Webhook: %s" % webhook)
            workflowReport = manageWebhook(webhook, cfg, use_cases)
            if workflowReport['success']:
                return jsonify(workflowReport), 200
            else:
                return jsonify(workflowReport), 500
         except Exception as e:
             logger.error('Failed to listen or action webhook: %s' % e, exc_info=True)
             return jsonify({'success':False}), 500

    else:
        return jsonify({'success':False, 'message':'Not JSON'}), 400

@app.route('/ews2case', methods=['GET'])
def ews2case():
    response = validateRequest(request)
    return response

@app.route('/QRadar2alert', methods=['POST'])
def QRadar2alert():
    response = validateRequest(request)
    return response

@app.route('/ELK2alert', methods=['POST'])
def ELK2alert():
    response = validateRequest(request)
    return response

@app.route('/version', methods=['GET'])
def getSynapseVersion():
    return jsonify({'version': '1.1.1'}), 200

if __name__ == '__main__':
    app.run(debug=cfg.getboolean('api', 'debug_mode'),
        host=cfg.get('api', 'host'),
        port=cfg.get('api', 'port'),
        threaded=cfg.get('api', 'threaded')
    )
