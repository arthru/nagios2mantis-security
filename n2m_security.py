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

import csv
import socket


class NagiosRequest(object):  # pragma: no cover
    def __init__(self, conn, resource):
        self._conn = conn
        self._resource = resource
        self._columns = []
        self._filter = []

    def call(self):
        if self._columns:
            return self._conn.call(str(self), self._columns)
        return self._conn.call(str(self))

    def __str__(self):
        request = 'GET %s' % (self._resource)
        if self._columns:
            request += '\nColumns: %s' % (' '.join(self._columns))
        if self._filter:
            for filter_line in self._filter:
                request += '\nFilter: %s' % (filter_line)
        return request + '\n\n'

    def columns(self, *args):
        self._columns = args
        return self

    def filter(self, filter_str):
        self._filter.append(filter_str)
        return self


class NagiosLivestatus(object):  # pragma: no cover
    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port

    def __getattr__(self, name):
        return NagiosRequest(self, name)

    def call(self, request, columns=None):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.hostname, self.port))
            s.send(request)
            s.shutdown(socket.SHUT_WR)
            csv_lines = csv.DictReader(s.makefile(), columns, delimiter=';')
            return list(csv_lines)
        finally:
            s.close()


class SecurityUpdatesChecker(object):
    def __init__(self):
        self.nagios = NagiosLivestatus('192.168.222.5', 6557)

    def _nagios_request(self):
        request = self.nagios.services
        request.columns('host_name', 'service_description', 'plugin_output',
                        'state')
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

    def check(self):
        self.check_errors()
        self.check_ok()

    def check_errors(self):
        nagios_errors = self._nagios_errors()
        for line in nagios_errors:
            mantis_ticket = self.find_ticket(line)
            if mantis_ticket:
                self.mantis_add_note(line)
            else:
                self.mantis_add_ticket(line)

    def check_ok(self):
        nagios_ok = self._nagios_ok()
        for line in nagios_ok:
            mantis_ticket = self.find_ticket(line)
            if mantis_ticket:  # is open
                self.mantis_close_ticket(line)

    def find_ticket(self, line):
        pass

    def mantis_add_note(self, line):
        pass

    def mantis_add_ticket(self, line):
        pass

    def mantis_close_ticket(self, line):
        pass
