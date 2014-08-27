#
#    Copyright (c) 2011-2012 Andrey Sibiryov <me@kobology.ru>
#    Copyright (c) 2012+ Anton Tyurin <noxiouz@yandex.ru>
#    Copyright (c) 2013+ Evgeny Safronov <division494@gmail.com>
#    Copyright (c) 2011-2014 Other contributors as noted in the AUTHORS file.
#
#    This file is part of Cocaine.
#
#    Cocaine is free software; you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as published by
#    the Free Software Foundation; either version 3 of the License, or
#    (at your option) any later version.
#
#    Cocaine is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public License
#    along with this program. If not, see <http://www.gnu.org/licenses/>.
#

__author__ = 'Evgeny Safronov <division494@gmail.com>'

from ..common import CocaineErrno


class ServiceError(Exception):
    def __init__(self, errnumber, reason):
        self.errno = errnumber
        self.reason = reason
        super(Exception, self).__init__("%s %s" % (self.errno, self.reason))


class InvalidApiVerison(ServiceError):
    def __init__(self, name, expected_version, got_version):
        message = "service `%s`invalid API version: expected `%d`, got `%d`" % (name, expected_version, got_version)
        super(InvalidApiVerison, self).__init__(CocaineErrno.INVALIDAPIVERISON, message)


class InvalidMessageType(ServiceError):
    pass


class ChokeEvent(Exception):
    pass


class Error(Exception):
    pass


class CommunicationError(Error):
    pass


class ConnectionError(CommunicationError):
    def __init__(self, address, reason):
        if len(address) == 2:
            host, port = address[:2]
            message = '{0}:{1} - {2}'.format(host, port, reason)
        elif len(address) == 4:
            host, port, flex, scope = address
            message = '{0}:{1} - {2}'.format(host, port, reason)
        else:
            message = '{0} - {1}'.format(address, reason)
        super(ConnectionError, self).__init__(message)


class ConnectionResolveError(ConnectionError):
    def __init__(self, address):
        super(ConnectionResolveError, self).__init__(address, 'could not resolve hostname "{0}"'.format(address))


class ConnectionRefusedError(ConnectionError):
    def __init__(self, address):
        super(ConnectionRefusedError, self).__init__(address, 'connection refused')


class ConnectionTimeoutError(ConnectionError):
    def __init__(self, address, timeout):
        super(ConnectionTimeoutError, self).__init__(address, 'timeout ({0:.3f}s)'.format(timeout))


class LocatorResolveError(ConnectionError):
    def __init__(self, name, address, reason):
        message = 'unable to resolve API for service "{0}" because {1}'.format(name, reason)
        super(LocatorResolveError, self).__init__(address, message)


class TimeoutError(CommunicationError):
    def __init__(self, timeout):
        super(TimeoutError, self).__init__('timeout ({0:.3f}s)'.format(timeout))


class DisconnectionError(CommunicationError):
    def __init__(self, name):
        super(DisconnectionError, self).__init__('Service {0} has been disconnected'.format(name))


class IllegalStateError(CommunicationError):
    pass
