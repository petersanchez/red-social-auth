import json
import httplib
import urllib
import time
import hashlib
import socket
import logging
from https_connection import VerifiedHTTPSConnection

class RequestError(Exception):
    def __init__(self, dict):
        self.status = 0
        if type(dict) == type({}):
            self.status = dict.get('status')
        super(RequestError, self).__init__(dict)

class RanOutOfTries(Exception):
    pass

logger = logging.getLogger(__name__)

class OAuth2Handler(object):
    TOKEN_DOMAIN = 'accounts.google.com'
    AUTH_URL = "/o/oauth2/auth"
    TOKEN_URL = "/o/oauth2/token"

    @classmethod
    def get_auth_url(klass, client_id, client_secret, redirect_uri, scopes=[], offline=False):
        scope_string = ' '.join(scopes)

        params = {
            'client_id' : client_id,
            'scope' : scope_string,
            'redirect_uri' : redirect_uri,
            'response_type' : 'code',
        }
        if offline:
            params['access_type'] = 'offline'
        params = urllib.urlencode(params)

        url = "https://%s%s?%s" % (klass.TOKEN_DOMAIN, klass.AUTH_URL, params)
        return url

    @classmethod
    def create_from_authorization_code(klass, authorization_code, client_id, client_secret, redirect_uri):

        headers = {"Content-type": "application/x-www-form-urlencoded"}
        params = urllib.urlencode({
            'client_id' : client_id,
            'client_secret' : client_secret,
            'code' : authorization_code,
            'redirect_uri' : redirect_uri,
            'grant_type' : 'authorization_code'
        })

        conn = VerifiedHTTPSConnection(klass.TOKEN_DOMAIN)
        conn.request("POST", klass.TOKEN_URL, params, headers)

        response = conn.getresponse()
        data = response.read()
        refresh_token = None
        access_token = None
        if response.status == 200:
            value = json.loads(data)
            access_token = value['access_token']
            refresh_token = value.get('refresh_token')
        else:
            dict = { 'status' : response.status }
            try:
                j = json.loads(data)
                dict.update(j)
            except:
                dict['data'] = data
            raise RequestError(dict)

        token = access_token
        if refresh_token:
            token = refresh_token
        cls = klass(token, client_id, client_secret)
        cls.access_token = access_token
        return cls


    def __init__(self, token, client_id, client_secret):

        assert token and client_id and client_secret

        self.client_id = client_id
        self.client_secret = client_secret

        # Token could be a refresh token
        # or an access token
        self.refresh_token = token
        self._access_token = token

        self.base_auth_args = {
            'client_id' : self.client_id,
            'client_secret' : self.client_secret,
        }

        self._customer_resource_id = None

    def _set_access_token(self, val):
        self._access_token = val

    def _get_access_token(self):
        if not self._access_token:
            self.update_access_token()
        return self._access_token
    access_token = property(_get_access_token, _set_access_token)

    def update_access_token(self):
        args = self.base_auth_args.copy()
        args['grant_type'] = 'refresh_token'
        args['refresh_token'] = self.refresh_token
        params = urllib.urlencode(args)

        headers = {"Content-type": "application/x-www-form-urlencoded"}
        conn = VerifiedHTTPSConnection(self.TOKEN_DOMAIN)
        conn.request("POST", self.TOKEN_URL, params, headers)

        response = conn.getresponse()
        data = response.read()
        val = None
        if response.status == 200:
            try:
                value = json.loads(data)
                val = value['access_token']
            except:
                pass

        self._access_token = val

    def request_retry(self, method, url, body=None, headers={}, expected_resp=200, num_retries=10):

        num_retries = int(num_retries)
        if num_retries < 0:
            raise ValueError("num_retries must be 0 or greater")

        mtries, mdelay = num_retries, 1
        socket_retries = num_retries
        while socket_retries > 0 and mtries > 0:
            try:
                try:
                    return self.request(method, url, body, headers, expected_resp)
                except SystemExit:
                    raise
                except RequestError, e:
                    # Error 500 is 'internal server error' and warrants a retry
                    # Error 503 is 'service unavailable' and warrants a retry
                    if e.status not in [500, 503]:
                        raise e

                logger.debug("Got %s from google. Retrying in %s" % (e.status, mdelay))
                mtries -= 1
                time.sleep(mdelay)
                mdelay *= 2

                # There was a successfull connection. So reset socket_retries
                socket_retries = num_retries

            except socket.error, e:
                # Socket errors are different
                # No need for incremental backoff
                # just wait 5 secs and try again.
                time.sleep(5)
                socket_retries -= 1
                logger.debug("Connection error: %s. Retrying in 5" % str(e))

        raise RanOutOfTries('Ran out of tries. %s' % e)

    def request(self, method, url, body=None, headers={}, expected_resp=200, allow_new_access_token=True):
        if not headers:
            headers = {}

        headers['Authorization'] = 'OAuth %s' % self.access_token

        conn = VerifiedHTTPSConnection(self.DOMAIN)

        conn.request(method, url, body, headers)

        response = conn.getresponse()
        if response.status == 401 and allow_new_access_token:
            self.update_access_token()
            return self.request(method, url, body, headers, expected_resp, False)

        try:
            data = response.read()
            if response.status == expected_resp:
                return data
            else:
                dict = { 'status' : response.status, 'raw' : data}
                try:
                    j = json.loads(data)
                    dict.update(j)
                except:
                    dict['data'] = data
                raise RequestError(dict)
        finally:
            conn.close()

class GooglePlus(OAuth2Handler):
    PEOPLE_URL = '/plus/v1/people/%s'
    DOMAIN = 'www.googleapis.com'

    def get_user(self, user='me'):
        url = self.PEOPLE_URL % user
        data = self.request('GET', url)
        try:
            return json.loads(data)
        except ValueError:
            raise RequestError({'data' : data + " is not valid json"})
