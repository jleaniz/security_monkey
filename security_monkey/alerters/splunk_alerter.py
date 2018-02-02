#     Copyright 2017 Netflix, Inc.
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
"""
.. module: security_monkey.tests.sso.test_azure
    :platform: Unix
.. version:: $$VERSION$$
.. moduleauthor::  Juan Leaniz <juan.leaniz@ubisoft.com>
"""

from security_monkey.alerters import custom_alerter
from splunk_http_event_collector import http_event_collector
from security_monkey import app

http_event_collector_key = "14960f9d-4c77-4c5c-adca-fca32c60c039"
http_event_collector_host = "https://ubisoft-splunk-hf.ubisoft.com:8088"
testevent = http_event_collector(http_event_collector_key, http_event_collector_host, input_type="raw")

# "name=\"{}\"".format(
#    item.db_item.id,
#    item.index,
#    item.account,
#    item.region,
#    item.name))

class SplunkAlerter(object):
    __metaclass__ = custom_alerter.AlerterType

    def report_watcher_changes(self, watcher):
        """
        Logs created, changed and deleted items for Splunk consumption.
        """

        for item in watcher.created_items:
            payload = {}
            payload.update({"name": "Created item: " + item.account + "" + item.name})
            payload.update({"host": "secmonkey.ubi.com"})
            app.logger.info("Sending new event to Splunk.")
            testevent.sendEvent(payload)

        for item in watcher.changed_items:
            payload = {}
            payload.update({"name": "Changed item: " + item.account + "" + item.name})
            payload.update({"host": "secmonkey.ubi.com"})
            app.logger.info("Sending new event to Splunk.")
            testevent.sendEvent(payload)

        for item in watcher.deleted_items:
            payload = {}
            payload.update({"name": "Deleted item: " + item.account + "" + item.name})
            payload.update({"host": "secmonkey.ubi.com"})
            app.logger.info("Sending new event to Splunk.")
            testevent.sendEvent(payload)

    def report_auditor_changes(self, auditor):
        for item in auditor.items:
            for issue in item.confirmed_new_issues:
                payload = {}
                payload.update({"name": "New issue: " + item.account + "" + item.name})
                payload.update({"host": "secmonkey.ubi.com"})
                app.logger.info("Sending new event to Splunk.")
                testevent.sendEvent(payload)

            for issue in item.confirmed_fixed_issues:
                payload = {}
                payload.update({"name": "Fixed issue: " + item.account + "" + item.name})
                payload.update({"host": "secmonkey.ubi.com"})
                app.logger.info("Sending new event to Splunk.")
                testevent.sendEvent(payload)

