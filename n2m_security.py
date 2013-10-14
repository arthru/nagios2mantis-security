#!/usr/bin/env python
#
# Copyright (C) 2013 Arthur Vuillard <arthur@hashbang.fr>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more detail.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <http://www.gnu.org/licenses/>.
#

import argparse
import yaml
from SOAPpy import WSDL
from mk_livestatus import NagiosSocket
from ConfigParser import RawConfigParser


class Config(RawConfigParser):
    def __init__(self, filename):
        RawConfigParser.__init__(self)
        self.read(filename)

        self.nagios_host = self.get('Nagios', 'host')
        self.nagios_port = int(self.get('Nagios', 'port'))

        self.mantis_wsdl = self.get('Mantis', 'wsdl')
        self.mantis_username = self.get('Mantis', 'username')
        self.mantis_password = self.get('Mantis', 'password')
        self.mantis_category = self.get('Mantis', 'category')
        self.mantis_project_id = self.get('Mantis', 'project_id')

        self.template_summary = self.get('Templates', 'summary')
        self.template_description = self.get('Templates', 'description')
        self.template_note = self.get('Templates', 'note')


class SecurityUpdatesChecker(object):
    def __init__(self, config):
        self.config = config
        self.nagios = NagiosSocket(config.nagios_host, config.nagios_port)
        self.mantis = WSDL.Proxy(config.mantis_wsdl)

    def _nagios_request(self):
        request = self.nagios.services
        request.columns('host_name', 'plugin_output', 'host_notes')
        request.filter('service_description = security')
        return request

    def _nagios_errors(self):
        request = self._nagios_request()
        request.filter('state != 0')
        return request.call()

    def _nagios_ok(self):
        request = self._nagios_request()
        request.filter('state = 0')
        return request.call()

    def check_errors(self):
        nagios_errors = self._nagios_errors()
        for line in nagios_errors:
            self.check_error(line)

    def check_error(self, line):
        line['packages'] = line['plugin_output'].split(': ')[1]
        mantis_issue = self.find_issue(line)
        if mantis_issue:
            self.mantis_add_note(mantis_issue, line)
        else:
            self.mantis_add_issue(line)

    def check_okays(self):
        nagios_ok = self._nagios_ok()
        for line in nagios_ok:
            self.check_okay(line)

    def check_okay(self, line):
        mantis_issue_id = self.find_issue(line)
        if mantis_issue_id:  # is open
            self.mantis_close_issue(mantis_issue_id, line)

    def find_issue(self, line):
        issue_id = self.mantis.mc_issue_get_id_from_summary(
            self.config.mantis_username,
            self.config.mantis_password,
            self.config.template_summary % line
        )
        return self.mantis.mc_issue_get(
            self.config.mantis_username,
            self.config.mantis_password,
            issue_id
        )

    def mantis_add_note(self, mantis_issue, line):
        self.mantis.mc_issue_note_add(
            self.config.mantis_username,
            self.config.mantis_password,
            mantis_issue_id,
            {'text': self.config.template_note % line}
        )

    def mantis_add_issue(self, line):
        if 'host_notes' in line and line['host_notes']:
            host_notes = yaml.load(line['host_notes'])
            project_id = host_notes['mantis_project_id']
        else:
            project_id = self.config.mantis_project_id
        issue = {
            'summary': self.config.template_summary % line,
            'description': self.config.template_description % line,
            'category': self.config.mantis_category,
            'project': {'id': project_id}
        }
        self.mantis.mc_issue_add(
            self.config.mantis_username,
            self.config.mantis_password,
            issue
        )

    def mantis_close_issue(self, issue_id, line):
        issue = {
            'status': 'resolved'
        }
        self.mantis.mc_issue_update(
            self.config.mantis_username,
            self.config.mantis_password,
            issue_id,
            issue
        )


def main():  # pragma: nocover
    parser = argparse.ArgumentParser(description='Sends Nagios security '
                                     'update alerts to Mantis')
    parser.add_argument('-c', '--configuration-file',
                        help='INI file containing configuration',
                        default='/etc/n2m_security.ini')
    args = parser.parse_args()

    config = Config(args.configuration_file)
    checker = SecurityUpdatesChecker(config.nagios, config.mantis)

    checker.check_errors()
    checker.chek_okays()


if __name__ == '__main__':  # pragma: nocover
    main()
