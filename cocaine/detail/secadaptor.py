#
# Mostly compy-pasted from cocaine-tools
#
from tornado import gen
from tornado.ioloop import IOLoop

from cocaine.services import Service
from cocaine.exceptions import CocaineError

import time


class SecureServiceError(CocaineError):
    pass


class Promiscuous(object):
    @gen.coroutine
    def fetch_token(self):
        raise gen.Return('')


class TVM(object):

    TYPE = 'TVM'

    def __init__(self, client_id, client_secret, name='tvm'):
        self._client_id = client_id
        self._client_secret = client_secret

        self._tvm = Service(name)

    @gen.coroutine
    def fetch_token(self):
        grant_type = 'client_credentials'

        channel = yield self._tvm.ticket_full(self._client_id, self._client_secret, grant_type, {})
        ticket = yield channel.rx.get()

        raise gen.Return(self._make_header(ticket))

    def _make_header(self, ticket):
        return '{} {}'.format(self.TYPE, ticket)


class SecureServiceAdaptor(object):

    def __init__(self, wrapped, secure, tok_update_sec=None):
        self._wrapped = wrapped
        self._secure = secure

        self._to_expire = None
        self._tok_update_sec = tok_update_sec

        if tok_update_sec:
            self._to_expire = time.time() + tok_update_sec

        self._token = None

    @gen.coroutine
    def connect(self, traceid=None):
        yield self._wrapped.connect(traceid)

    def disconnect(self):
        return self._wrapped.disconnect()

    @gen.coroutine
    def _get_token(self):
        try:
            if self._to_expire:
                if time.time() > self._to_expire:
                    # tok_update_sec should be set in __init__ when
                    # self._to_expire is valid
                    self._token = yield self._secure.fetch_token()
                    self._to_expire = time.time() + self.tok_update_sec
                elif not self._token:  # init state
                    self._token = yield self._secure.fetch_token()
            else:
                    self._token = yield self._secure.fetch_token()
        except Exception as e:
            raise SecureServiceError(
                'failed to fetch secure token: {}'.format(err))

        raise gen.Return(self._token)

    def __getattr__(self, name):
        @gen.coroutine
        def wrapper(*args, **kwargs):
            kwargs['authorization'] = yield self._get_token()
            raise gen.Return(
                (yield getattr(self._wrapped, name)(*args, **kwargs))
            )

        return wrapper


class SecureServiceFabric(object):

    @staticmethod
    def make_secure_adaptor(service, mod, client_id, client_secret, tok_update_sec=None):
        if mod == 'TVM':
            return SecureServiceAdaptor(
                service, TVM(client_id, client_secret), tok_update_sec)

        return SecureServiceAdaptor(service, Promiscuous(), tok_update_sec)
