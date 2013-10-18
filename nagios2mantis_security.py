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
import sqlite3
import yaml
from SOAPpy import WSDL
from mk_livestatus import Socket
from ConfigParser import RawConfigParser
from parse import parse


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
        self.mantis_project_id = int(self.get('Mantis', 'default_project_id'))
        self.mantis_status_id = int(self.get('Mantis', 'resolved_status_id'))

        self.template_summary = self.get('Templates', 'summary')
        self.template_description = self.get('Templates', 'description')
        self.template_note = self.get('Templates', 'note')
        self.template_close = self.get('Templates', 'close')

        self.sqlite_filename = self.get('DB', 'sqlite_filename')


class DbLink(object):
    def __init__(self, sqlite_filename):
        self.db = sqlite3.connect(sqlite_filename)
        self.db.execute(
            'create table if not exists nagios_mantis_link ('
            'hostname text, issue_id integer);'
        )

    def add(self, hostname, issue_id):
        db_issue_id = self.get_issue_id(hostname)
        assert db_issue_id is None, 'This hostname already has a ticket (%d)'\
            % (issue_id)
        request_params = {'hostname': hostname, 'issue_id': issue_id}
        self.db.execute('insert into nagios_mantis_link (hostname, issue_id) '
                        'values (:hostname, :issue_id);', request_params)
        self.db.commit()

    def delete(self, issue_id):
        self.db.execute(
            'delete from nagios_mantis_link where issue_id = :issue_id ;',
            {'issue_id': issue_id}
        )
        self.db.commit()

    def get_issue_id(self, hostname):
        cursor = self.db.cursor()
        cursor.execute(
            'select issue_id from nagios_mantis_link where hostname = '
            ':hostname;',
            {'hostname': hostname}
        )
        try:
            rows = cursor.fetchall()
            if len(rows) == 0:
                return None
            return rows[0][0]
        finally:
            cursor.close()


class SecurityUpdatesChecker(object):
    def __init__(self, config):
        self.config = config
        self.nagios = Socket((config.nagios_host, config.nagios_port))
        self.mantis = WSDL.Proxy(config.mantis_wsdl)
        self.db = DbLink(config.sqlite_filename)

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
            notified_packages = self.find_notified_packages(mantis_issue)
            line['all_packages'] = ' '.join(notified_packages)
        else:
            line['all_packages'] = line['packages']
        if (mantis_issue and
                mantis_issue['status']['id'] != self.config.mantis_status_id):
            self.mantis_add_note(mantis_issue, line)
        else:
            self.mantis_add_issue(line)

    def check_okays(self):
        nagios_ok = self._nagios_ok()
        for line in nagios_ok:
            self.check_okay(line)

    def check_okay(self, line):
        mantis_issue = self.find_issue(line)
        if mantis_issue:
            notified_packages = self.find_notified_packages(mantis_issue)
            line['all_packages'] = ' '.join(notified_packages)
        if (mantis_issue and
                mantis_issue['status']['id'] != self.config.mantis_status_id):
            self.mantis_close_issue(mantis_issue, line)

    def find_issue(self, line):
        issue_id = self.db.get_issue_id(line['host_name'])
        if not issue_id:
            return None
        return self.mantis.mc_issue_get(
            self.config.mantis_username,
            self.config.mantis_password,
            issue_id
        )

    def find_notified_packages(self, mantis_issue):
        template_clean = lambda s: s.replace('%(', '{').replace(')s', '}')
        packages = set()
        parsed_desc = parse(
            template_clean(self.config.template_description),
            mantis_issue['description']
        )
        packages.update(parsed_desc['packages'].split(' '))
        if mantis_issue['notes']:
            for note in mantis_issue['notes']:
                parsed_note = parse(
                    template_clean(self.config.template_note),
                    note['text']
                )
                packages.update(parsed_note['packages'].split(' '))
        return packages

    def find_new_packages(self, mantis_issue, current_packages):
        notified_packages = self.find_notified_packages(mantis_issue)
        new_packages = []
        for package in current_packages.split(' '):
            if package not in notified_packages:
                new_packages.append(package)
        return new_packages

    def mantis_add_note(self, mantis_issue, line):
        new_packages = self.find_new_packages(mantis_issue, line['packages'])
        if not new_packages:
            return
        self.mantis.mc_issue_note_add(
            self.config.mantis_username,
            self.config.mantis_password,
            mantis_issue['id'],
            {'text': self.config.template_note % {
                'packages': ' '.join(new_packages)
            }}
        )

        line['all_packages'] += ' ' + ' '.join(new_packages)
        issue = self.get_issue_for_update(mantis_issue)
        issue['summary'] = self.config.template_summary % line
        self.mantis.mc_issue_update(
            self.config.mantis_username,
            self.config.mantis_password,
            mantis_issue['id'],
            issue
        )

    def get_nagios_project_id(self, line):
        if 'host_notes' in line and line['host_notes']:
            host_notes = yaml.load(line['host_notes'])
            return host_notes['mantis_project_id']
        return self.config.mantis_project_id

    def mantis_add_issue(self, line):
        project_id = self.get_nagios_project_id(line)
        issue = {
            'summary': self.config.template_summary % line,
            'description': self.config.template_description % line,
            'category': self.config.mantis_category,
            'project': {'id': project_id}
        }
        issue_id = self.mantis.mc_issue_add(
            self.config.mantis_username,
            self.config.mantis_password,
            issue
        )
        self.db.add(line['host_name'], issue_id)

    def mantis_close_issue(self, mantis_issue, line):
        self.mantis.mc_issue_note_add(
            self.config.mantis_username,
            self.config.mantis_password,
            mantis_issue['id'],
            {'text': self.config.template_close % line}
        )

        issue = self.get_issue_for_update(mantis_issue)
        issue['summary'] = self.config.template_summary % line
        issue['status'] = {'id': self.config.mantis_status_id}
        self.mantis.mc_issue_update(
            self.config.mantis_username,
            self.config.mantis_password,
            mantis_issue['id'],
            issue
        )
        self.db.delete(mantis_issue['id'])

    def get_issue_for_update(self, mantis_issue):
        issue = {}
        for key in ['category', 'project', 'description', 'summary']:
            if hasattr(mantis_issue[key], '_asdict'):  # pragma: nocover
                issue[key] = mantis_issue[key]._asdict()
            else:
                issue[key] = mantis_issue[key]
        return issue


def main():  # pragma: nocover
    parser = argparse.ArgumentParser(description='Sends Nagios security '
                                     'update alerts to Mantis')
    parser.add_argument('-c', '--configuration-file',
                        help='INI file containing configuration',
                        default='/etc/nagios2mantis_security.ini')
    args = parser.parse_args()

    config = Config(args.configuration_file)
    checker = SecurityUpdatesChecker(config)

    checker.check_errors()
    checker.check_okays()


if __name__ == '__main__':  # pragma: nocover
    main()
