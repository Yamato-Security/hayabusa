# YEATargetfile (sigma/tools/sigma/backends/yea.py)
# python3 tools/sigmac rules/windows/process_creation/win_apt_chafer_mar18.yml --config elk-windows --target yea

import re
import sigma
from .base import BaseBackend
from .mixins import RulenameCommentMixin, MultiRuleOutputMixin
from sigma.parser.condition import SigmaConditionTokenizer, SigmaParseError
import yaml

class YeaBackend(BaseBackend, RulenameCommentMixin):
    """Converts Sigma rule into Splunk Search Processing Language (SPL)."""
    identifier = "yea"
    active = True
    interval = None
    title = None

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        base = yaml.safe_load(str(sigmaparser.parsedyaml))
        return yaml.dump(base)

    def finalize(self):
        """
        Is called after the last file was processed with generate(). The right place if this backend is not intended to
        look isolated at each rule, but generates an output which incorporates multiple rules, e.g. dashboards.
        """
        print("==============")
        pass