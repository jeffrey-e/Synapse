import logging
from core.modules import Main

class Automators(Main):
    def __init__(self, cfg, use_case_config):
        self.logger = logging.getLogger(__name__)
        self.logger.info('Initiating SMTP Automators')

        self.cfg = cfg
        self.use_case_config = use_case_config
