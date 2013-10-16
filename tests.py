import unittest
import mock

from nagios2mantis_security import SecurityUpdatesChecker, Config, DbLink


class MantisMock(object):
    def __init__(self, url):
        self.mc_issue_note_add = mock.Mock()
        self.mc_issue_add = mock.Mock()
        self.mc_issue_get = mock.Mock()
        self.mc_issue_update = mock.Mock()


class MantisIssueNotFoundMock(MantisMock):
    def __init__(self, url):
        super(MantisIssueNotFoundMock, self).__init__(url)
        self.mc_issue_get_id_from_summary = mock.Mock(return_value=None)


class TestN2MSecurity(unittest.TestCase):
    def setUp(self):
        self.config = Config('nagios2mantis_security.ini')
        self.config.sqlite_filename = ':memory:'

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_mantis_add_issue(self):
        checker = SecurityUpdatesChecker(self.config)
        checker.mantis.mc_issue_add.return_value = 23
        line = {
            'packages': 'python-django python-soappy',
            'host_name': 'localhost',
            'all_packages': 'python-django python-soappy',
        }
        checker.mantis_add_issue(line)

        checker.mantis.mc_issue_add.assert_called_once_with(
            'mantis_login',
            'mantis_password',
            {
                'category': 'General',
                'project': {'id': 1},
                'description': 'The following packages have security updates '
                               'available : python-django python-soappy',
                'summary': 'Security updates available for host localhost : '
                           'python-django python-soappy'
            }
        )

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_mantis_close_ticket(self):
        checker = SecurityUpdatesChecker(self.config)

        line = {
            'host_name': 'localhost',
            'plugin_output': 'OK',
            'host_notes': '',
            'all_packages': 'python-django'
        }
        mantis_issue = {
            'id': 1,
            'category': 'General',
            'project': {'id': 1},
            'summary': 'This is a summary',
            'description': 'This is a description',
        }
        checker.mantis_close_issue(mantis_issue, line)

        checker.mantis.mc_issue_note_add.assert_called_once_with(
            'mantis_login',
            'mantis_password',
            1,
            {'text': 'No more security update for this host.\n'
             'The packages that have been updated are : python-django'}
        )
        mantis_issue['status'] = {'id': 80}
        del mantis_issue['id']
        mantis_issue['summary'] = 'Security updates available for host '\
                                  'localhost : python-django'
        checker.mantis.mc_issue_update.assert_called_once_with(
            'mantis_login',
            'mantis_password',
            1,
            mantis_issue
        )

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_get_nagios_project_id_with_notes(self):
        checker = SecurityUpdatesChecker(self.config)

        project_id = checker.get_nagios_project_id({
            'host_notes': 'mantis_project_id: 3'
        })
        self.assertEquals(3, project_id)

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_get_nagios_project_id_without_notes(self):
        checker = SecurityUpdatesChecker(self.config)

        project_id = checker.get_nagios_project_id({})
        self.assertEquals(1, project_id)

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_mantis_add_note_no_new_packages(self):
        checker = SecurityUpdatesChecker(self.config)
        checker.mantis_add_note(
            {
                'id': 42,
                'description': 'The following packages have security updates '
                               'available : python-django python-soappy',
                'notes': [],
            },
            {'packages': 'python-django python-soappy'}
        )

        self.assertFalse(checker.mantis.mc_issue_note_add.called)
        self.assertFalse(checker.mantis.mc_issue_update.called)

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_mantis_add_note_new_packages(self):
        checker = SecurityUpdatesChecker(self.config)
        checker.mantis_add_note(
            {
                'id': 42,
                'description': 'The following packages have security updates '
                               'available : python-django',
                'notes': [],
                'category': 'Default',
                'project': {'id': 1},
                'summary': 'this is a summary',
            },
            {
                'host_name': 'host',
                'packages': 'python-django python-soappy',
                'all_packages': 'python-django python-soappy',
            }
        )
        checker.mantis.mc_issue_note_add.assert_called_once_with(
            'mantis_login',
            'mantis_password',
            42,
            {'text': 'This packages also have security updates : '
                     'python-soappy'}
        )
        checker.mantis.mc_issue_update.assert_called_once_with(
            'mantis_login',
            'mantis_password',
            42,
            {
                'category': 'Default',
                'project': {'id': 1},
                'description': 'The following packages have security updates '
                               'available : python-django',
                'summary': 'Security updates available for host host : '
                           'python-django python-soappy python-soappy'
            }
        )

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_mantis_find_new_packages(self):
        checker = SecurityUpdatesChecker(self.config)
        new_packages = checker.find_new_packages(
            {
                'description': 'The following packages have security updates '
                               'available : python-django',
                'notes': [
                    {'text': 'This packages also have security updates : '
                             'python-soappy'},
                    {'text': 'This packages also have security updates : '
                             'python-mock'},

                ],
            },
            'python-django python-soappy python-mock python-flask'
        )
        self.assertEquals(new_packages, ['python-flask'])

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_find_issue_not_found(self):
        checker = SecurityUpdatesChecker(self.config)
        issue = checker.find_issue({'host_name': 'localhost'})
        self.assertIsNone(issue)

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_find_issue_found(self):
        checker = SecurityUpdatesChecker(self.config)
        mantis_issue = {'id': 42}
        checker.db.add('localhost', 42)
        checker.mantis.mc_issue_get.return_value = mantis_issue

        issue = checker.find_issue({'host_name': 'localhost'})

        self.assertEquals(issue, mantis_issue)
        checker.mantis.mc_issue_get.assert_called_once_with(
            'mantis_login',
            'mantis_password',
            42
        )

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_nagios_errors(self):
        checker = SecurityUpdatesChecker(self.config)
        checker.nagios.call = mock.Mock()
        checker._nagios_errors()

        checker.nagios.call.assert_called_once_with(
            'GET services\n'
            'Columns: host_name plugin_output host_notes\n'
            'Filter: service_description = security\n'
            'Filter: state != 0\n\n',
            ('host_name', 'plugin_output', 'host_notes')
        )

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_nagios_ok(self):
        checker = SecurityUpdatesChecker(self.config)
        checker.nagios.call = mock.Mock()
        checker._nagios_ok()

        checker.nagios.call.assert_called_once_with(
            'GET services\n'
            'Columns: host_name plugin_output host_notes\n'
            'Filter: service_description = security\n'
            'Filter: state = 0\n\n',
            ('host_name', 'plugin_output', 'host_notes')
        )

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_check_errors(self):
        checker = SecurityUpdatesChecker(self.config)
        line1 = {
            'host_name': 'localhost',
            'plugin_output': 'Packages: python-django',
            'host_notes': '',
        }
        line2 = {
            'host_name': 'host2',
            'plugin_output': 'Packages: python-django',
            'host_notes': '',
        }
        checker.nagios.call = mock.Mock(return_value=[line1, line2])
        checker.check_error = mock.Mock()

        checker.check_errors()

        self.assertEquals(2, checker.check_error.call_count)
        checker.check_error.assert_any_call(line1)
        checker.check_error.assert_any_call(line2)

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_check_okays(self):
        checker = SecurityUpdatesChecker(self.config)
        line1 = {
            'host_name': 'localhost',
            'plugin_output': 'OK',
            'host_notes': '',
        }
        line2 = {
            'host_name': 'host2',
            'plugin_output': 'OK',
            'host_notes': '',
        }
        checker.nagios.call = mock.Mock(return_value=[line1, line2])
        checker.check_okay = mock.Mock()

        checker.check_okays()

        self.assertEquals(2, checker.check_okay.call_count)
        checker.check_okay.assert_any_call(line1)
        checker.check_okay.assert_any_call(line2)

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_check_error_add_note(self):
        checker = SecurityUpdatesChecker(self.config)
        line1 = {
            'host_name': 'localhost',
            'plugin_output': 'Packages: python-django',
            'host_notes': '',
        }
        mantis_issue = {
            'id': 42,
            'status': {'id': 10},
            'notes': [],
            'description': 'The following packages have security updates '
                           'available : python-django',
        }
        checker.db.add('localhost', 42)
        checker.mantis.mc_issue_get.return_value = mantis_issue
        checker.mantis_add_note = mock.Mock()

        checker.check_error(line1)

        checker.mantis_add_note.assert_called_once_with_args(
            mantis_issue, line1)

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_check_error_add_issue_ticket_resolved(self):
        checker = SecurityUpdatesChecker(self.config)
        line1 = {
            'host_name': 'localhost',
            'plugin_output': 'Packages: python-django',
            'host_notes': '',
        }
        mantis_issue = {
            'id': 42,
            'status': {'id': 80},
            'notes': [],
            'description': 'The following packages have security updates '
                           'available : python-django',
        }
        checker.db.add('localhost', 42)
        checker.mantis.mc_issue_get.return_value = mantis_issue
        checker.mantis_add_issue = mock.Mock()

        checker.check_error(line1)

        checker.mantis_add_issue.assert_called_once_with_args(line1)

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_check_error_add_issue_no_ticket(self):
        checker = SecurityUpdatesChecker(self.config)
        line1 = {
            'host_name': 'localhost',
            'plugin_output': 'Packages: python-django',
            'host_notes': '',
        }
        checker.mantis_add_issue = mock.Mock()

        checker.check_error(line1)

        checker.mantis_add_issue.assert_called_once_with_args(line1)

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_check_okay_close(self):
        checker = SecurityUpdatesChecker(self.config)
        line1 = {
            'host_name': 'localhost',
            'plugin_output': 'OK',
            'host_notes': '',
        }
        mantis_issue = {
            'id': 42,
            'status': {'id': 10},
            'notes': [],
            'description': 'The following packages have security updates '
                           'available : python-django',
        }
        checker.db.add('localhost', 42)
        checker.mantis.mc_issue_get.return_value = mantis_issue
        checker.mantis_close_issue = mock.Mock()

        checker.check_okay(line1)

        checker.mantis_close_issue.assert_called_once_with_args(
            mantis_issue, line1)

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_check_okay_already_closed(self):
        checker = SecurityUpdatesChecker(self.config)
        line1 = {
            'host_name': 'localhost',
            'plugin_output': 'OK',
            'host_notes': '',
        }
        mantis_issue = {
            'id': 42,
            'status': {'id': 80},
            'notes': [],
            'description': 'The following packages have security updates '
                           'available : python-django',
        }
        checker.db.add('localhost', 42)
        checker.mantis.mc_issue_get.return_value = mantis_issue
        checker.mantis_close_issue = mock.Mock()

        checker.check_okay(line1)

        self.assertFalse(checker.mantis_close_issue.called)

    @mock.patch('SOAPpy.WSDL.Proxy', MantisMock)
    def test_check_okay_no_issue(self):
        checker = SecurityUpdatesChecker(self.config)
        line1 = {
            'host_name': 'localhost',
            'plugin_output': 'OK',
            'host_notes': '',
        }
        checker.mantis_close_issue = mock.Mock()

        checker.check_okay(line1)

        self.assertFalse(checker.mantis_close_issue.called)


class DbLinkTest(unittest.TestCase):
    def test_add_twice(self):
        db = DbLink(':memory:')
        db.add('localhost', 42)
        with self.assertRaises(AssertionError):
            db.add('localhost', 42)

        cursor = db.db.cursor()
        cursor.execute('select * from nagios_mantis_link;')
        rows = cursor.fetchall()
        self.assertEquals(rows, [(u'localhost', 42)])

if __name__ == '__main__':
    unittest.main()
