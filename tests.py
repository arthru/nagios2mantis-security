import unittest
import mock
from StringIO import StringIO

from n2m_security import SecurityUpdatesChecker, Config


class SocketMock:
    content = ''

    def __init__(self, arg1, arg2):
        pass

    def connect(self, arg):
        pass

    def send(self, arg):
        pass

    def shutdown(self, arg):
        pass

    def close(self):
        pass

    def makefile(self):
        return StringIO(self.content)


class ErrorSocketMock(SocketMock):
    content = 'localhost;Packages: python-django;'\
              'mantis_project_id: 1'


class NoNotesErrorSocketMock(SocketMock):
    content = 'localhost;Packages: python-django;'


class OkSocketMock(SocketMock):
    content = 'localhost;OK;'


class MantisMock(object):
    def __init__(self, url):
        self.mc_issue_get_id_from_summary = mock.Mock(return_value=1)
        self.mc_issue_note_add = mock.Mock()
        self.mc_issue_add = mock.Mock()
        self.mc_issue_update = mock.Mock()


class MantisIssueNotFoundMock(MantisMock):
    def __init__(self, url):
        super(MantisIssueNotFoundMock, self).__init__(url)
        self.mc_issue_get_id_from_summary = mock.Mock(return_value=None)


class TestN2MSecurity(unittest.TestCase):
    def setUp(self):
        self.config = Config('n2m_security.ini')

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    @mock.patch('socket.socket', ErrorSocketMock)
    def test_errors_add_note(self):
        checker = SecurityUpdatesChecker(self.config)
        checker.check_errors()

        mantis = checker.mantis
        mantis.mc_issue_get_id_from_summary.assert_called_once_with(
            'mantis_login',
            'mantis_password',
            'Security updates available for host localhost'
        )
        mantis.mc_issue_note_add.assert_called_once_with(
            'mantis_login',
            'mantis_password',
            1,
            {'text': 'This packages also have security updates : python-django'}
        )

    @mock.patch('SOAPpy.WSDL.Proxy', MantisIssueNotFoundMock)
    @mock.patch('socket.socket', ErrorSocketMock)
    def test_errors_add_issue(self):
        checker = SecurityUpdatesChecker(self.config)
        checker.check_errors()

        mantis = checker.mantis
        mantis.mc_issue_get_id_from_summary.assert_called_once_with(
            'mantis_login',
            'mantis_password',
            'Security updates available for host localhost'
        )
        mantis.mc_issue_add.assert_called_once_with(
            'mantis_login',
            'mantis_password',
            {
                'category': 'General',
                'project': {'id': 1},
                'description': 'The following packages have security updates available : python-django',
                'summary': 'Security updates available for host localhost'
            }
        )

    @mock.patch('SOAPpy.WSDL.Proxy', MantisIssueNotFoundMock)
    @mock.patch('socket.socket', NoNotesErrorSocketMock)
    def test_errors_add_issue_no_notes(self):
        checker = SecurityUpdatesChecker(self.config)
        checker.check_errors()

        mantis = checker.mantis
        mantis.mc_issue_get_id_from_summary.assert_called_once_with(
            'mantis_login',
            'mantis_password',
            'Security updates available for host localhost'
        )
        mantis.mc_issue_add.assert_called_once_with(
            'mantis_login',
            'mantis_password',
            {
                'category': 'General',
                'project': {'id': '1'},
                'description': 'The following packages have security updates available : python-django',
                'summary': 'Security updates available for host localhost'
            }
        )

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    @mock.patch('socket.socket', OkSocketMock)
    def test_ok_close_issue(self):
        checker = SecurityUpdatesChecker(self.config)
        checker.check_ok()

        mantis = checker.mantis
        mantis.mc_issue_get_id_from_summary.assert_called_once_with(
            'mantis_login',
            'mantis_password',
            'Security updates available for host localhost'
        )
        mantis.mc_issue_update.assert_called_once_with(
            'mantis_login',
            'mantis_password',
            1,
            {'status': 'resolved'}
        )


if __name__ == '__main__':
    unittest.main()
