import os
import ssl
import socket
import httplib
import urllib2


class VerifiedHTTPSConnection(httplib.HTTPSConnection):
    path = os.path.abspath(
        os.path.join(os.path.dirname(__file__),
        'cacerts.txt'),
    )

    def connect(self):
        # overrides the version in httplib so that we do
        #    certificate verification
        sock = socket.create_connection((self.host, self.port), self.timeout)
        if hasattr(self, '_tunnel_host') and self._tunnel_host:
            self.sock = sock
            self._tunnel()
        # wrap the socket using verification with the root
        #    certs in trusted_root_certs
        self.sock = ssl.wrap_socket(sock,
                                    self.key_file,
                                    self.cert_file,
                                    cert_reqs=ssl.CERT_REQUIRED,
                                    ca_certs=self.path)

class VerifiedHTTPSHandler(urllib2.HTTPSHandler):
    def __init__(self, connection_class = VerifiedHTTPSConnection):
        self.specialized_conn_class = connection_class
        urllib2.HTTPSHandler.__init__(self)

    def https_open(self, req):
        return self.do_open(self.specialized_conn_class, req)


https_handler = VerifiedHTTPSHandler()
url_opener = urllib2.build_opener(https_handler)
urllib2.install_opener(url_opener)
