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

from SOAPpy import WSDL
from mk_livestatus import Query, NagiosSocket
from ConfigParser import RawConfigParser


class Config(RawConfigParser):
    def __init__(self, filename):
        RawConfigParser.__init__(self)
        self.read(filename)

        self.nagios_host = self.get('Nagios', 'host')
        self.nagios_port = self.get('Nagios', 'port')
        self.mantis_wsdl = self.get('Mantis', 'wsdl')
        self.mantis_username = self.get('Mantis', 'username')
        self.mantis_password = self.get('Mantis', 'password')

    @property
    def nagios(self):
        return NagiosSocket(self.nagios_host, self.nagios_port)
    
    @property
    def mantis(self):
        return WSDL(self.mantis_wsdl)


class SecurityUpdatesChecker(object):
    def __init__(self, nagios, mantis):
        self.nagios = nagios
        self.mantis = mantis

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


def main():
    parser = argparse.ArgumentParser(description='Sends Nagios security update alerts to Mantis')
    parser.add_argument('-c', '--configuration-file', help='INI file containing configuration', default='/etc/n2m_security.ini')
    args = parser.parse_args()
    
    config = Config(args.configuration_file)
    checker = SecurityUpdatesChecker(config.nagios, config.mantis)

    checker.check()


if __name__ == '__main__':
    main()
