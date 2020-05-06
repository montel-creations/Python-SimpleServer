NAMAFILE = 'Telkomsel Opok v1'
REQ = ''
LHOST = '127.0.0.1'
LPORT = 8080
FQUERY = ('dGVsa29tLnR1eXVsY3J5cHRvcy5jb20vaXBrLWJpbi9pcGsucG5nL25wYXpvbmUvMDAvaHR0cC8=').decode('base64')
MQUERY = ''
BQUERY = ''
RQUERY = ('di53aGF0c2FwcC5jb20uYmVyYmFnaW1hbmZhYXQuY28uaWQ=').decode('base64')
CQUERY = ''
IQUERY = ''
IMETHOD = 0
ILINE = 0
ISPLIT = 0
ADMODE = 0
RPORT = 0
RPATH = 0
CUSHDR0 = ('Q29ubmVjdGlvbg==').decode('base64')
VALHDR0 = ('a2VlcC1hbGl2ZQ==').decode('base64')
CUSHDR1 = ('WC1PbmxpbmUtSG9zdA==').decode('base64')
VALHDR1 = ('di53aGF0c2FwcC5jb20uaXBrem9uZS5jby5pZA==').decode('base64')
CUSHDR2 = ''
VALHDR2 = ''
CUSHDR3 = ''
VALHDR3 = ''
KEEP = ('d3d3Lmdvb2dsZS5jb20=').decode('base64')
RHTTP = 0
RHTTPS = 1
SBUFF = 1024
TIMEOUT = 60
PHOST = ''
PPORT = 0
PTYPE = 0
import os, sys, select, socket, random, time, urlparse, threading, urllib2, SocketServer, BaseHTTPServer, base64
W = '\x1b[0m'
R = '\x1b[31m'
G = '\x1b[1;32m'
O = '\x1b[33m'
B = '\x1b[34m'
P = '\x1b[35m'
C = '\x1b[36m'
GR = '\x1b[37m'

def color(s):
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(0.0 / 90)


X = '\n\n\t [!] Remode       : Sane4tsu'
color(G + X)
X = '\t [!] Enscrypt     : Ivan Kollev'
color(G + X)
X = '\t [!] InjectConfig : Ferry Kirdan Agustin'
color(G + X)
X = '\t [!] Groups       : New Phreaker Ababil'
color(G + X)
X = '\t [!] ScriptConfig : Injection Telkomsel\n'
color(G + X)

def main():
    D = ' [!] Input Your Password'
    color(GR + D)
    like = 'Ferry Kirdan Agustin'
    user_input = raw_input(' [!] Password : ')
    if user_input != like:
        sys.exit(' [!] Incorrect Password, terminating... \n')
    print ' [!] User is logged in!\n'


if __name__ == '__main__':
    main()
ra = lambda text: text.decode('ascii', 'ignore')
ru = lambda text: text.decode('utf-8', 'ignore')
DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), '%s' % NAMAFILE))

class Info():

    def __init__(self, get):
        self.get = get

    def get_info(self):
        if self.get.lower() == 'uid':
            return '0x00000000'
        if self.get.lower() == 'heap':
            return '0x8000-0x1000000'
        if self.get.lower() == 'name':
            return 'simpleserver'
        if self.get.lower() == 'about':
            return 'linux version'
        if self.get.lower() == 'ver':
            return '1.0.0b'
        if self.get.lower() == 'date':
            return '07-09-2014'
        if self.get.lower() == 'by':
            return 'inunxlabs'
        if self.get.lower() == 'mail':
            return 'inunxlabs@gmail.com'


if getattr(socket, 'socket', None) is None:
    raise ImportError('socket.socket missing, proxy support unusable')
ra = lambda text: text.decode('ascii', 'ignore')
_defaultproxy = None
_orgsocket = socket.socket

class ProxyError(Exception):
    pass


class GeneralProxyError(ProxyError):
    pass


class HTTPError(ProxyError):
    pass


_generalerrors = (
 'success', 'invalid data', 'not connected', 'not available', 'bad proxy type', 'bad input')

def setdefaultproxy(proxytype=None, addr=None, port=None, rdns=True, username=None, password=None, useragent=None):
    global _defaultproxy
    _defaultproxy = (
     proxytype,
     addr,
     port,
     rdns,
     username,
     password,
     useragent)


def wrapmodule(module):
    if _defaultproxy != None:
        module.socket.socket = socksocket
    else:
        raise GeneralProxyError((4, 'no proxy specified'))
    return


class socksocket(socket.socket):

    def __init__(self, family=socket.AF_INET, tipe=socket.SOCK_STREAM, proto=0, _sock=None, headers=None, newline=None):
        _orgsocket.__init__(self, family, tipe, proto, _sock)
        if _defaultproxy != None:
            self.__proxy = _defaultproxy
        else:
            self.__proxy = (None, None, None, None, None, None, None)
        self.__proxysockname = None
        self.__proxypeername = None
        self.__httptunnel = True
        self.__headers = headers
        self.__newline = newline
        return

    def __recvall(self, count):
        data = self.recv(count)
        while len(data) < count:
            d = self.recv(count - len(data))
            if not d:
                raise GeneralProxyError((0, 'connection closed unexpectedly'))
            data = data + d

        return data

    def sendall(self, content, *args):
        if not self.__httptunnel:
            content = self.__rewriteproxy(content)
        return super(socksocket, self).sendall(content, *args)

    def __rewriteproxy(self, header):
        host, endpt = (None, None)
        hdrs = header.split('%s' % self.__newline)
        for hdr in hdrs:
            if hdr.lower().startswith('host:'):
                host = hdr
            elif hdr.lower().startswith('get') or hdr.lower().startswith('post'):
                endpt = hdr

        if host and endpt:
            hdrs.remove(host)
            hdrs.remove(endpt)
            host = host.split(' ')[1]
            endpt = endpt.split(' ')
            if self.__proxy[4] != None and self.__proxy[5] != None:
                hdrs.insert(0, self.__getauthheader())
            hdrs.insert(0, 'Host: %s' % host)
            hdrs.insert(0, '%s http://%s%s %s' % (endpt[0],
             host,
             endpt[1],
             endpt[2]))
        return '%s' % self.__newline.join(hdrs)

    def __getauthheader(self):
        auth = self.__proxy[4] + ':' + self.__proxy[5]
        return 'Proxy-Authorization: Basic ' + base64.b64encode(auth)

    def setproxy(self, proxytype=None, addr=None, port=None, rdns=True, username=None, password=None, useragent=None):
        self.__proxy = (proxytype,
         addr,
         port,
         rdns,
         username,
         password,
         useragent)

    def getproxysockname(self):
        return self.__proxysockname

    def getproxypeername(self):
        return _orgsocket.getpeername(self)

    def getpeername(self):
        return self.__proxypeername

    def __negotiatehttp(self, destaddr, destport):
        if not self.__proxy[3]:
            addr = socket.gethostbyname(destaddr)
        else:
            addr = destaddr
        if self.__headers:
            headers = [
             self.__headers]
        else:
            headers = [
             'CONNECT ',
             addr,
             ':',
             str(destport),
             ' HTTP/1.1%s' % self.__newline]
            headers += ['Host: ', destaddr, '%s' % self.__newline]
            if self.__proxy[6] is not None:
                headers += ['User-Agent: ', unicode(self.__proxy[6]), '%s' % self.__newline]
            if self.__proxy[4] != None and self.__proxy[5] != None:
                headers += [self.__getauthheader(), '%s' % self.__newline]
            headers.append('%s' % self.__newline)
            self.sendall(ra(('').join(headers).encode()))
            resp = self.recv(1)
            while resp.find(('\r\n\r\n').encode()) == -1:
                resp = resp + self.recv(1)

        self.__proxysockname = ('0.0.0.0', 0)
        self.__proxypeername = (addr, destport)
        return

    def connect(self, destpair):
        if type(destpair) not in (list, tuple) or len(destpair) < 2 or not isinstance(destpair[0], basestring) or type(destpair[1]) != int:
            raise GeneralProxyError((5, _generalerrors[5]))
        if self.__proxy[0] == 0:
            if self.__proxy[2] != None:
                portnum = self.__proxy[2]
            else:
                portnum = 8080
            _orgsocket.connect(self, (self.__proxy[1], portnum))
            _ports = (22, 443, 465, 563, 585, 587, 636, 706, 993, 995, 2083, 2211,
                      2483, 2949, 4747, 6679, 6697, 8883, 19999)
            if destpair[1] in _ports:
                self.__negotiatehttp(destpair[0], destpair[1])
            else:
                self.__httptunnel = False
        else:
            if self.__proxy[0] == 1:
                if self.__proxy[2] != None:
                    portnum = self.__proxy[2]
                else:
                    portnum = 8080
                _orgsocket.connect(self, (self.__proxy[1], portnum))
                self.__negotiatehttp(destpair[0], destpair[1])
            else:
                if self.__proxy[0] == None:
                    _orgsocket.connect(self, (destpair[0], destpair[1]))
                else:
                    raise GeneralProxyError((4, _generalerrors[4]))
        return


logs = False

def ServerUpdate():
    print 'ok'


class Server():

    def __init__(self):
        self.long = 8
        self.name = Info('name').get_info()
        self.ver = Info('ver').get_info()
        self.form = Info('about').get_info()
        self.auth = Info('by').get_info()
        self.mail = Info('mail').get_info()
        self.noyes = [ru('No'), ru('Yes')]
        self.version = [ru('Default'), ru('HTTP/1.0'), ru('HTTP/1.1')]
        self.method = [ru('HEAD'),
         ru('GET'),
         ru('POST'),
         ru('DELETE'),
         ru('CONNECT'),
         ru('OPTIONS'),
         ru('TRACE'),
         ru('PUT')]
        self.line = [ru('\\r\\n'), ru('\\n')]
        self.split = [ru('Default'),
         ru('%s' % (self.line[ILINE] * ILINE)),
         ru('%s' % (self.line[ILINE] * ILINE)),
         ru('%s' % (self.line[ILINE] * ILINE)),
         ru('%s' % (self.line[ILINE] * ILINE)),
         ru('%s' % (self.line[ILINE] * ILINE))]

    def subs(self, data='', cut=False):
        if data:
            data = data
        else:
            data = 'None'
        if cut:
            if len(data) > 5:
                data = '%s...' % data[:5]
        return data

    def about(self, title=''):
        self.info = []
        self.info.append('[ %s ]%s\n' % (title, '=' * (self.long - len(title) - 5)))
        self.info.append('Name : %s\n' % self.name)
        self.info.append('Version : %s\n' % self.ver)
        self.info.append('Dev : %s\n' % self.auth)
        self.info.append('Email : %s\n' % self.mail)
        self.info.append('\n\n')
        return ru(('').join(self.info))

    def config(self, title=''):
        self.info = []
        self.info.append('[ %s ]%s\n' % (title, '=' * (self.long - len(title) - 5)))
        self.info.append('Config File : \n')
        self.info.append('- DirFile : %s\n' % DIR)
        self.info.append('Local Host :\n')
        self.info.append('- %s\n' % LHOST)
        self.info.append('Local Port :\n')
        self.info.append('- %s\n' % str(LPORT))
        self.info.append('HTTP Query :\n')
        self.info.append('- Front Query : %s\n' % self.subs(FQUERY))
        self.info.append('- Middle Query : %s\n' % self.subs(MQUERY))
        self.info.append('- Back Query : %s\n' % self.subs(BQUERY))
        self.info.append('- Reverse Query : %s\n' % self.subs(RQUERY))
        self.info.append('- Inject Query : %s\n' % self.subs(IQUERY))
        self.info.append('- Inject Method : %s\n' % self.method[IMETHOD])
        self.info.append('- Inject Newline : %s\n' % self.line[ILINE])
        self.info.append('- Inject Splitline : %s\n' % self.split[ISPLIT])
        self.info.append('- Remove Port : %s\n' % self.noyes[RPORT])
        self.info.append('- Remove Path : %s\n' % self.noyes[RPATH])
        self.info.append('- Url Replacer : %s\n' % self.subs(CQUERY))
        self.info.append('- Request Version : %s\n' % self.version[RHTTP])
        self.info.append('- Advanced Mode : %s\n' % self.noyes[ADMODE])
        self.info.append('HTTP Header :\n')
        self.info.append('- Custom Header 1 : %s\n' % self.subs(CUSHDR0))
        self.info.append('- Header Value 1 : %s\n' % self.subs(VALHDR0))
        self.info.append('- Custom Header 2 : %s\n' % self.subs(CUSHDR1))
        self.info.append('- Header Value 2 : %s\n' % self.subs(VALHDR1))
        self.info.append('- Custom Header 3 : %s\n' % self.subs(CUSHDR2))
        self.info.append('- Header Value 3 : %s\n' % self.subs(VALHDR2))
        self.info.append('- Custom Header 4 : %s\n' % self.subs(CUSHDR3))
        self.info.append('- Header Value 4 : %s\n' % self.subs(VALHDR3))
        self.info.append('Server Config :\n')
        self.info.append('- Keep Server : %s\n' % self.subs(KEEP))
        self.info.append('- HTTPS Connection : %s\n' % self.noyes[RHTTPS])
        self.info.append('- Tunnel Proxy : %s\n' % self.noyes[PTYPE])
        self.info.append('- Server Buffer : %s\n' % str(SBUFF))
        self.info.append('- Connection Timeout : %s\n' % str(TIMEOUT))
        self.info.append('Proxy Host :\n')
        self.info.append('- %s\n' % self.subs(PHOST))
        self.info.append('Proxy Port :\n')
        self.info.append('- %s\n' % str(PPORT))
        self.info.append('\n\n')
        return ru(('').join(self.info))

    def log(self, title=''):
        self.info = []
        self.info.append('%s %s\n' % (title, '' * (self.long - len(title) - 5)))
        self.info.append('\n\n')
        return ru(('').join(self.info))

    def show(self):
        sys.stderr.write(self.about('About'))
        time.sleep(1)
        sys.stderr.write(self.log('Inject Ready...'))


class Pinger():

    def __init__(self):
        self.host = []
        for server in self.KEEP.split('|'):
            if server:
                self.host.append(server)

    def check(self):
        if self.host:
            try:
                request = urllib2.Request('http://%s/' % self.host[random.randint(0, len(self.host) - 1)])
                request.add_header('Accept-Encoding', 'identity, *;q=0')
                request.add_header('Connection', 'close')
                proxy_handler = urllib2.ProxyHandler({'http': '%s:%s' % ('127.0.0.1', self.LPORT)})
                opener = urllib2.build_opener(proxy_handler)
                urllib2.install_opener(opener)
                urllib2.urlopen(request)
            except:
                pass


def LogWindow(flag=False):
    global logs
    logs = flag


class QueryHandler():

    def __init__(self, command='', path='/', headers={}, https=False, phost='', pport=0):
        self.command = command
        self.path = path
        self.headers = headers
        self.https = https
        self.phost = phost
        self.pport = pport

    def get_path(self, path):
        if '/' in path:
            host, path = path.split('/', 1)
            path = '/%s' % path
        else:
            host = path
            path = '/'
        fport = False
        if self.https:
            port = 443
        else:
            port = 80
        if ':' in host:
            _host, _port = host.rsplit(':', 1)
            try:
                port = int(_port)
                host = _host
                fport = True
            except:
                pass

        return (
         fport,
         host,
         port,
         path)

    def get_query(self):
        if self.https:
            url = 'https://%s/' % self.path
        else:
            url = self.path
        url_scm, _, _, _, _, _ = urlparse.urlparse(url)
        if len(FQUERY.split('/')) > 2:
            cgi_http = 'http/'
            if cgi_http in FQUERY.lower():
                url_cgi = url.split(cgi_http)
                if len(url_cgi) > 1:
                    url = '%s://%s' % (url_scm, url_cgi.pop())
            else:
                url = url.replace(FQUERY, '')
        if len(MQUERY.split('/')) > 2:
            url = url.replace(MQUERY, '')
        if len(BQUERY.split('/')) > 2:
            url = url.replace(BQUERY, '')
        url_len = len(url_scm) + 3
        url_path = url[url_len:]
        if CQUERY:
            cquery_list = CQUERY.split('|')
            for cquery in cquery_list:
                try:
                    old, new = cquery.split('>')
                    url_path = url_path.replace(old, new)
                except:
                    pass

        fport, host, port, path = self.get_path('%s%s' % (FQUERY, url_path))
        advhost = host
        if fport and not RPORT:
            path = '%s:%s%s%s%s' % (host,
             port,
             MQUERY,
             path,
             BQUERY)
        else:
            path = '%s%s%s%s' % (host,
             MQUERY,
             path,
             BQUERY)
        fport, host, port, path = self.get_path(path)
        if self.https:
            fport = True
            path = '%s:%s' % (host, port)
        else:
            if self.phost and self.pport or ADMODE:
                if RQUERY:
                    if MQUERY.startswith('/'):
                        path = '%s%s%s' % (url[:url_len], RQUERY, path)
                    else:
                        path = '%s%s%s%s' % (url[:url_len],
                         RQUERY,
                         MQUERY,
                         path)
                elif fport and not RPORT:
                    path = '%s%s:%s%s' % (url[:url_len],
                     host,
                     port,
                     path)
                else:
                    path = '%s%s%s' % (url[:url_len], host, path)
            else:
                _, path = path.split('/', 1)
                path = '/%s' % path
        cur_header = 'proxy-connection'
        if cur_header in self.headers and not self.phost and not self.pport:
            del self.headers[cur_header]
        cur_header = 'connection'
        if not self.https and not PTYPE:
            if cur_header in self.headers:
                del self.headers[cur_header]
            self.headers[cur_header] = 'close'
        cur_header = 'host'
        if cur_header in self.headers:
            del self.headers[cur_header]
            if fport and not RPORT and not self.https:
                self.headers[cur_header] = '%s:%s' % (host, port)
            else:
                self.headers[cur_header] = host
        if RQUERY:
            cur_header = 'host'
            if cur_header in self.headers:
                del self.headers[cur_header]
            self.headers[cur_header] = RQUERY
            cur_header = 'x-online-host'
            if cur_header in self.headers:
                del self.headers[cur_header]
            if fport and not self.https:
                self.headers[cur_header] = '%s:%s' % (host, port)
            else:
                self.headers[cur_header] = '%s' % host
        if ADMODE:
            cur_header = 'host'
            if cur_header in self.headers:
                if RQUERY:
                    del self.headers[cur_header]
                    self.headers[cur_header] = '%s' % RQUERY
                    cur_header = 'x-online-host'
                    if cur_header in self.headers:
                        del self.headers[cur_header]
                    if fport and not self.https:
                        self.headers[cur_header] = '%s:%s' % (advhost, port)
                    else:
                        self.headers[cur_header] = '%s' % advhost
                elif self.phost and self.pport:
                    del self.headers[cur_header]
                    advhost = advhost.replace(FQUERY, '').replace(MQUERY, '').replace(BQUERY, '')
                    if fport and not self.https:
                        self.headers[cur_header] = '%s:%s' % (advhost, port)
                    else:
                        self.headers[cur_header] = '%s' % advhost
        if CUSHDR0 and not VALHDR0:
            cur_header = CUSHDR0.lower()
            if cur_header in self.headers:
                del self.headers[cur_header]
        if CUSHDR0 and VALHDR0:
            cur_header = CUSHDR0.lower()
            if cur_header in self.headers:
                del self.headers[cur_header]
            self.headers[cur_header] = VALHDR0
        if CUSHDR1 and not VALHDR1:
            cur_header = CUSHDR1.lower()
            if cur_header in self.headers:
                del self.headers[cur_header]
        if CUSHDR1 and VALHDR1:
            cur_header = CUSHDR1.lower()
            if cur_header in self.headers:
                del self.headers[cur_header]
            self.headers[cur_header] = VALHDR1
        if CUSHDR2 and not VALHDR2:
            cur_header = CUSHDR2.lower()
            if cur_header in self.headers:
                del self.headers[cur_header]
        if CUSHDR2 and VALHDR2:
            cur_header = CUSHDR2.lower()
            if cur_header in self.headers:
                del self.headers[cur_header]
            self.headers[cur_header] = VALHDR2
        if CUSHDR3 and not VALHDR3:
            cur_header = CUSHDR3.lower()
            if cur_header in self.headers:
                del self.headers[cur_header]
        if CUSHDR3 and VALHDR3:
            cur_header = CUSHDR3.lower()
            if cur_header in self.headers:
                del self.headers[cur_header]
            self.headers[cur_header] = VALHDR3
        if RPORT:
            cur_port = ':%s' % port
            path = path.replace(cur_port, '')
            cur_list = ('host', 'x-online-host')
            for cur_header in cur_list:
                if cur_header in self.headers and ':' in self.headers[cur_header]:
                    rhost, _ = self.headers[cur_header].split(':')
                    del self.headers[cur_header]
                    self.headers[cur_header] = rhost

        header = self.headers
        uahdr = 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)'
        cur_header = 'user-agent'
        if cur_header in self.headers:
            uahdr = self.headers[cur_header]
        self.del_garbage()
        return (
         path,
         header,
         uahdr,
         host,
         port,
         advhost)

    def del_garbage(self):
        del self.command
        del self.path
        del self.headers
        del self.https
        del self.phost
        del self.pport


class ProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def __getattr__(self, item):
        if item.startswith('do_'):
            return self.do_COMMAND

    def do_COMMAND(self):
        self.get_urlcheck()
        self.get_headercheck()
        self.get_recv_headers()
        self.get_proxy()
        query = QueryHandler(self.command, self.path, self.headers, self.https, self.phost, self.pport)
        self.path, self.headers, self.uahdr, self.host, self.port, self.advhost = query.get_query()
        self.get_newline()
        self.get_requestline()
        self.get_injectline()
        self.get_send_inject()
        self.get_send_headers()
        soc = self.proxy_sock()
        try:
            if self.connect_to(soc, self.host, self.port, self.advhost):
                data = ra('%s%s' % (self.get_injectline(), self.newline)).encode('hex')
                for header, value in self.headers.items():
                    data += ra('%s: %s%s' % (str(header).title(), value, self.newline)).encode('hex')

                post_header = 'content-length'
                if post_header in self.headers:
                    data += ra(self.newline).encode('hex')
                    data += self.rfile.read(int(self.headers[post_header])).encode('hex')
                    data += ra(self.newline).encode('hex')
                data += ra('%s%s' % (self.newline, self.get_send_end())).encode('hex')
                data = data.decode('hex')
                while data:
                    byte = soc.send(data)
                    data = data[byte:]

                self.get_response_data(soc)
                self.send_connection_close(soc)
                self.del_garbage()
        except socket.error as msg:
            self.send_connection_error(msg)
            self.send_connection_close(soc)
            return
        except:
            return

    def do_CONNECT(self):
        if RHTTPS:
            self.get_urlcheck()
            self.get_headercheck()
            self.get_recv_headers()
            self.get_proxy()
            query = QueryHandler(self.command, self.path, self.headers, self.https, self.phost, self.pport)
            self.path, self.headers, self.uahdr, self.host, self.port, self.advhost = query.get_query()
            self.get_newline()
            self.get_requestline()
            self.get_injectline()
            self.get_send_inject()
            self.get_send_headers()
            soc = self.proxy_sock()
            try:
                if self.connect_to(soc, self.host, self.port, self.advhost):
                    data = '%s 200 Connection Established\r\nProxy-Agent: %s/%s' % (self.request_version, Info('name').get_info().replace(' ', ''), Info('ver').get_info()[:3])
                    self.send_response_data('%s\r\n' % data)
                    self.send_response_data('\r\n')
                    self.get_response_header(data)
                    self.get_response_data(soc)
                    self.send_connection_close(soc)
                    self.del_garbage()
            except socket.error as msg:
                self.send_connection_error(msg)
                self.send_connection_close(soc)
                return
            except:
                return

        else:
            self.send_connection_error((501, 'method not allowed'))
            self.connection.close()
            return

    def get_urlcheck(self):
        self.https = False
        if self.command == 'CONNECT':
            self.https = True

    def get_headercheck(self):
        header_check = {}
        for header, value in self.headers.items():
            if header.find('\t') == -1 and header.find('\t') == -1:
                header_check[str(header).lower()] = value

        self.headers = header_check

    def get_proxy(self):
        self.phost = ''
        self.pport = 0
        self.puser = None
        self.ppass = None
        if ':' in PHOST and not PPORT:
            plist = PHOST.split('>')
            count = len(plist)
            while 1:
                count -= 1
                if count >= 0:
                    plist = plist[random.randint(0, len(plist) - 1)]
                    if '@' in plist and plist:
                        try:
                            self.puser, self.ppass = plist.split('@')[1].split(':')
                            plist = plist.split('@')[0]
                        except:
                            pass

                    if ':' in plist and plist:
                        try:
                            self.phost, self.pport = plist.split(':')
                            self.pport = int(self.pport)
                        except:
                            pass

                        break
                else:
                    break

        else:
            if PHOST and PPORT:
                self.phost, self.pport = PHOST, PPORT
        return

    def proxy_sock(self):
        if IQUERY and self.https or self.https:
            data = ra('%s%s' % (self.get_injectline(), self.newline))
            for header, value in self.headers.items():
                data += ra('%s: %s%s' % (str(header).title(), value, self.newline))

            soc = socksocket(headers=data, newline=self.newline)
        else:
            soc = socksocket(newline=self.newline)
        if self.phost and self.pport:
            soc.setproxy(PTYPE, self.phost, self.pport, rdns=True, username=self.puser, password=self.puser, useragent=self.uahdr)
        return soc

    def connect_to(self, soc, host, port, advhost):
        try:
            if ADMODE:
                host, port = advhost, port
            soc.setblocking(1)
            soc.connect((host, port))
            return 1
        except socket.error as msg:
            self.send_connection_error(msg)
            self.send_connection_close(soc)
            return 0
        except:
            return 0

    def get_newline(self):
        self.newline = ['\r\n', '\n'][ILINE]

    def get_requestline(self):
        if RHTTP == 1:
            self.request_version = 'HTTP/1.0'
        else:
            if RHTTP == 2:
                self.request_version = 'HTTP/1.1'
        self.requestline = '%s %s %s' % (self.command, self.path, self.request_version)

    def get_injectline(self):
        if IQUERY:
            meth = [
             'HEAD',
             'GET',
             'POST',
             'DELETE',
             'CONNECT',
             'OPTIONS',
             'TRACE',
             'PUT'][IMETHOD]
            if '/' in IQUERY:
                host, path = IQUERY.split('/', 1)
                path = '/%s' % path
            else:
                host = IQUERY
                path = '/'
            if self.phost and self.pport or ADMODE:
                path = 'http://%s%s' % (host, path)
            self.splitline = self.newline * 3
            if ISPLIT:
                self.splitline = self.newline * ISPLIT
            self.injectline = '%s %s HTTP/1.1%sHost: %s%s' % (meth,
             path,
             self.newline,
             host, self.splitline)
            return '%s%s' % (self.injectline, self.requestline)
        return self.requestline

    def get_send_end(self):
        if IQUERY:
            return self.newline
        return ''

    def get_recv_headers(self):
        self.send_connection_logger('+++++[ Receive Request ]+++++\r\nFrom Address - %s:%s\r\n%s\r\n' % (self.client_address[0], self.client_address[1], self.requestline))
        for header, value in self.headers.items():
            self.send_connection_logger('%s: %s\r\n' % (str(header).title(), value))

        self.send_connection_logger('\r\n')

    def get_send_inject(self):
        if IQUERY:
            self.send_connection_logger('+++++[ Send Injection ]+++++\r\n')
            if self.phost and self.pport:
                self.send_connection_logger('Using Proxy - Loocked\r\n')
            else:
                if ADMODE:
                    self.send_connection_logger('Using Host - Loocked\r\n')
                else:
                    self.send_connection_logger('Using Server - Loocked\r\n')
            for inject in self.splitline[0].split(self.newline):
                self.send_connection_logger('No: Loocked\r\n')

            self.send_connection_logger('\r\n')

    def get_send_headers(self):
        self.send_connection_logger('+++++[ Send Request ]+++++\r\n')
        if self.phost and self.pport:
            self.send_connection_logger('Using Proxy - Loocked\r\n')
        else:
            if ADMODE:
                self.send_connection_logger('Using Host - Loocked\r\n')
            else:
                self.send_connection_logger('Using Server - Loocked\r\n')
        self.send_connection_logger('Config: Ferry Kirdan Agustin\r\n')
        for header, value in self.headers.items():
            self.send_connection_logger('%s: %s\r\n' % (str(header).title(), value))

        self.send_connection_logger('\r\n')

    def find_double_newline(self, data):
        pos1 = data.find('\n\r\n')
        if pos1 >= 0:
            pos1 += 3
        pos2 = data.find('\n\n')
        if pos2 >= 0:
            pos2 += 2
        if pos1 >= 0:
            if pos2 >= 0:
                return min(pos1, pos2)
            return pos1
        else:
            return pos2

    def get_data_splitter(self, data):
        if data.split('\r\n\r\n')[0].split(' ')[0] in ('HTTP/0.9', 'HTTP/1.0', 'HTTP/1.1'):
            return 1
        return 0

    def get_response_header(self, data):
        if not self.https:
            index = self.find_double_newline(data)
            if index >= 0:
                data = str(data[:index].split('\r\n\r\n')[0])
                if self.get_data_splitter(data):
                    self.send_connection_logger('+++++[ Receive Response ]+++++\r\n%s\r\n' % data)
                    self.send_connection_logger('\r\n')
        else:
            if self.get_data_splitter(data):
                self.send_connection_logger('+++++[ Receive Response ]+++++\r\n%s\r\n' % data)
                self.send_connection_logger('\r\n')

    def get_response_data(self, soc):
        iw = [
         self.connection, soc]
        ow = []
        count = 0
        timeout = 0
        while 1:
            timeout += 1
            ins, _, exs = select.select(iw, ow, iw, 3)
            if exs:
                break
            if ins:
                for resp in ins:
                    try:
                        data = resp.recv(SBUFF)
                        if data:
                            if resp is soc:
                                if IQUERY:
                                    if self.get_data_splitter(data):
                                        count += 1
                                    if not self.https:
                                        if count % 2 == 0:
                                            count = 0
                                            self.get_response_header(data)
                                            self.send_response_data(data)
                                    else:
                                        for idata in data.split('\r\n\r\n'):
                                            if count == 1 and not idata.startswith('HTTP/'):
                                                self.send_response_data(idata)

                                else:
                                    self.get_response_header(data)
                                    self.send_response_data(data)
                            else:
                                while data:
                                    byte = soc.send(data)
                                    data = data[byte:]

                            timeout = 0
                        else:
                            break
                    except:
                        break

            if timeout == TIMEOUT:
                break

    def send_response_data(self, data):
        self.wfile.write(data)

    def send_connection_close(self, soc):
        soc.close()
        self.connection.close()

    def send_connection_error(self, msg, page=True):
        try:
            code, message = msg
        except:
            self.send_connection_error((501, 'unknown error'))

        message = str(message).capitalize()
        self.send_connection_logger('+++++[ Connection Error ]+++++\r\n')
        self.send_connection_logger('%s: %s\r\n\r\n' % (str(code), message))
        if page:
            self.send_error(502, '%s.' % message)

    def send_connection_logger(self, data):
        if logs:
            sys.stderr.write(data)

    def del_garbage(self):
        del self.https
        del self.path
        del self.headers
        del self.uahdr
        del self.host
        del self.port
        del self.advhost
        del self.newline
        del self.requestline
        del self.injectline
        del self.phost
        del self.pport
        del self.puser
        del self.ppass


class ThreadingHTTPServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):

    def handle_error(self, request, client_address):
        pass


class HTTPProxyService():

    def __init__(self):
        self.httpd = ThreadingHTTPServer((LHOST, LPORT), ProxyHandler)
        self.httpd.allow_reuse_address = True

    def serve_forever(self):
        self.httpd.serve_forever()


class Serverx():

    def run(self):
        LogWindow(True)
        HTTPProxyService().serve_forever()

    def pinger(self):
        while 1:
            time.sleep(random.randint(30, 300))
            Pinger().check()


if __name__ == '__main__':
    Server().show()
    services = [threading.Thread(target=Serverx().run, args=()), threading.Thread(target=Serverx().pinger, args=())]
    for serving in services:
        serving.start()
