# Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
# Copyright (C) 2020 Panther Labs Inc
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import collections
from datetime import datetime, timedelta
from timeit import default_timer
from typing import Any, Dict, List

from .analysis_api import AnalysisAPIClient
from .logging import get_logger
from .rule import Rule, COMMON_MODULE_RULE_ID

_CACHE_DURATION = timedelta(minutes=5)


class Engine:
    """The engine that runs Python rules."""
    logger = get_logger()

    def __init__(self) -> None:
        self._last_update = datetime.utcfromtimestamp(0)
        self._log_type_to_rules: Dict[str, List[Rule]] = collections.defaultdict(list)
        self._analysis_client = AnalysisAPIClient()
        self.populate_rules()

    def populate_rules(self) -> None:
        """Import all rules."""
        start = default_timer()
        rules = self.get_rules()
        end = default_timer()
        self.logger.info('Retrieved rules in {} seconds'.format(end - start))
        start = default_timer()

        # Importing COMMON module
        for index, raw_rule in enumerate(rules):
            if raw_rule['id'] == COMMON_MODULE_RULE_ID:
                Rule(raw_rule['id'], raw_rule['body'])
                del rules[index]
                break
        for raw_rule in rules:
            rule = Rule(raw_rule['id'], raw_rule['body'])
            for log_type in raw_rule['resourceTypes']:
                self._log_type_to_rules[log_type].append(rule)
        end = default_timer()
        self.logger.info('Imported rules in {} seconds'.format(end - start))
        self._last_update = datetime.utcnow()

    def get_rules(self) -> List[Dict[str, str]]:
        """Retrieves all enabled rules.

        Returns:
            An array of Dict['id': rule_id, 'body': rule_body]
        """
        return self._analysis_client.get_enabled_rules()

    def analyze(self, log_type: str, event: Dict[str, Any]) -> List[str]:
        """Analyze an event by running all the rules that apply to the log type.

        Returns:
            ['rule-id-1', 'rule-id-3']  # rules that matched

        """
        if datetime.utcnow() - self._last_update > _CACHE_DURATION:
            self.populate_rules()

        matched: List[str] = []

        for rule in self._log_type_to_rules[log_type]:
            result = rule.run(event)
            if result is True:
                matched.append(rule.rule_id)
            elif isinstance(result, Exception):
                # TODO Add reporting of errors in the UI
                self.logger.error('failed to run rule {} {}'.format(type(result).__name__, result))

        return matched
