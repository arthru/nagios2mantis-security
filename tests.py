import unittest
import mock
from StringIO import StringIO

from n2m_security import SecurityUpdatesChecker


LIVESTATUS_CONTENT = '''localhost;security;Packages: python-django;2'''


class SocketMock:
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
        return StringIO(LIVESTATUS_CONTENT)


class TestN2MSecurity(unittest.TestCase):
    @mock.patch('socket.socket', SocketMock)
    def test_new_ticket(self):
        checker = SecurityUpdatesChecker()
        checker.check()


if __name__ == '__main__':
    unittest.main()
