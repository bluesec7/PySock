#!/usr/bin/python
# -*- coding: utf-8 -*- 

import gzip, os, re, sys, socket, ssl, select, struct, threading, time, urlparse, mimetools, StringIO, zlib
from Queue import Queue

'''

PySock for Android
~For Intercepting data between Client Server and Modify them
This script works with system libs
So you don't have to install any library

Except you need Python2.7

@author note
Still needs improvent
Fix Some Bugs
etc

this project provide:
*.http proxy server [yes]
*.script injecting [not yet]
*.hostname checking [yes]
*.caching (usually saving pkt) [yes]
*.replacement [yes]
*.SSLStrip support (by default) [yes]
*.Redirect desired Android app [yes]

Some useful HTTP Headers does not supported yet:
*.Proxy-Connection (for HTTP/1.1)


NOTE:
This program does not works if the app uses HSTS (eg Chrome Browser)
You should change the string replacing at line 135 for better work with sslstrip
Response Redirection is not saved yet

Usage:
pyrhon pysock.py <pkg_name>
'''

__author__ = 'bluesec7'
# Search for following Headers and replace the value
http_request_replace = {
'Proxy-Connection':'keep-alive',
'X-PySock':'true'
}
http_response_replace = {
}

def get_id(name):
    # search for pkg name and return owner id
    # change this path to work with Linux
    # but Linux have many path for program including /usr/bin /usr/sbin etc :P
    # so you can modify this script to work with Linux
    data = '/data/data'
    app_list = os.listdir(data)
    mean = []
    for app in app_list:
        #print app, os.stat('%s/%s'%(data,app))
        if app == name:
            return os.stat('%s/%s'%(data,app)).st_uid
        elif name in app:
            mean.append(app)
    for x in mean:
        print('[ ? ] Did you mean: %r ?'%x)
    raise NameError('No such pkg: %r'%(name))


class SockHandler(object):
    buff_recv = 1024*64 # used for recving from server
    buff_send = 1024*64 # used for recving from client
    reverse_proxy = None
    ssl_mode = False
    save = False
    direct = False
    tmp = ''
    http_mode = False
    def __init__(self, *client):
        self.client, self.addr = client
        print client
        try:
            self.handle()
        except Exception as e:
            print('SockHandler error : %r'%e)
        finally:
            self.on_close()
            
    def on_close(self):
        try:
            self.client.shutdown(socket.SHUT_WR)
        except socket.error as  e:
            pass
        '''for c in self.inputs:
            try:
                if c != self.client:
                    c.close()
                    self.inputs.remove(c)
            except: pass'''
        self.conn.close()
        self.client.close()
        print self.addr,'Closed'

    def get_dest(self):
        try:
            ori = self.client.getsockopt(socket.SOL_IP,80,16)
            dest_port, dest_addr = struct.unpack("!2xH4s8x",ori)
            self.real_server = socket.inet_ntoa(dest_addr), int(dest_port)
        except Exception as e:
            print("Unknown destination : %r"%e)
            return
        else:
            return self.real_server

    def create_conn(self):
        if self.reverse_proxy:
            host,port = self.reverse_proxy
            port = int(port)
        else:
            result = self.get_dest()
            if result:
                host, port = result
                #port = int(port)
            else:
                return
        # connect
        if (host) == ('127.0.0.1') and port == lport:
            print 'Direct connection'
            self.direct = True
            return
        if self.ssl_mode:
            context = ssl._create_unverified_context()
            sock = socket.socket(socket.AF_INET)
            conn = context.wrap_socket(sock)
            try:
                conn.connect((host,port))
            except Exception as e:
                print ('SSL Connection error : %r'%e)
                return
            else:
                print ('Connection Open from %s:%d'%(self.addr))
                return conn

        else:
            conn = socket.socket()
            try:
               conn.connect((host,port))
            except Exception as e:
               print ('Connection error : %r'%e)
               return
            else:
               print ('Connection Open from %s:%d'%(self.addr))
               return conn
        
    def http_handler(self):
        self.http_request = ReadHTTP()
        host = None
        while True:
            if self.q.empty():
                continue
            item = self.q.get()
            self.q.task_done()
            #print repr(item), time.ctime(time.time())
            if host:
                # pkt already sent
                print self.conn
                # support for sslstrip
                item = re.sub('http://','https://', item)
                # Headers replacement don't work
                self.conn.send(item)
                print repr(item), time.ctime(time.time())
                #self.q.task_done()
                From = 'From %s:%d'%(self.client.getpeername())
                if self.save:
                    request = ''.join([item])
                    detailed = '%s\n%s\n%s\n%s\n%s\n'%('#'*32, From, '#'*32,request,'='*32)
                    f = open('pysock_result','ab')
                    f.write(detailed)
                    f.close()
                continue
            # let's take it into read_http
            HTTP = self.http_request.read_http(item)
            #self.q.task_done()
            if self.http_request.headers_ok and not host:
                method, uri, version = self.http_request.request_line.strip().split(' ',2)
                parsed_uri = urlparse.urlparse(uri)
                # check host
                if self.http_request.headers.has_key('host'):
                    host = self.http_request.headers['host']
                    # find port
                    find_port = re.search(':[\d]+',host)
                    if find_port:
                        port = int(host[find_port.start()+1:find_port.end()])
                        host = host[:find_port.start()]
                    print 'Host:',host
                    if uri.startswith('https://'):
                        if not find_port:
                            port = 443
                        sock = socket.socket()
                        context = ssl._create_unverified_context()   
                        conn = context.wrap_socket(sock)
                        try:
                            conn.connect((host,port))
                        except Exception as e:
                            print 'HTTPS Sock Error',e
                            return self.on_close()
                    else:
                        if not find_port:
                            port = 80
                        conn = socket.socket()
                        try:
                            conn.connect((host,port))
                        except Exception as e:
                            print 'HTTP Sock Error',e
                            return self.on_close()
                    self.inputs.append(conn)
                    self.conn = conn
                    print self.conn
                    print('Connected HTTP(S) to %s:%d'%(host,port))
                    print '# Request #'
                    self.conn.send(self.http_request.request_line)
                    print repr(self.http_request.request_line)
                    new_headers = self.http_request.headers
                    # replace
                    for modh in http_request_replace:
                        new_headers[modh] = http_request_replace[modh]
                        print modh,'replaced wtih', http_request_replace[modh]
                    new_headers = '\r\n'.join( [ x + ': ' + str(new_headers[x]) for x in new_headers ] )
                    new_headers += '\r\n\r\n'
                    self.conn.send(new_headers)
                    print (new_headers)
                    #self.conn.send(self.http_request.headers_str)
                    #print repr(self.http_request.headers_str)
                    msg = self.http_request.body
                    while msg:
                        msg = msg[self.conn.send(msg):]
                    print repr(self.http_request.body)
                    From = 'From %s:%d'%(self.client.getpeername())
                    if self.save:
                        request = ''.join([self.http_request.request_line,self.http_request.headers_str,self.http_request.body])
                        detailed = '%s\n%s\n%s\n%s\n%s\n'%('#'*32, From, '#'*32,request,'='*32)
                        f = open('pysock_result','ab')
                        f.write(detailed)
                        f.close()
                else:
                    print 'No host'
                    return self.on_close()

    
    def shttp_handler(self):
        self.http_response = ReadHTTP()
        sent = False
        chunked = False
        data = ''
        chunkdata = ''
        host = None
        chunklen = None
        while True:
            if self.qr.empty():
                continue
            #item = u'%s'%(self.qr.get()).encode('utf8')
            item = self.qr.get()
            self.qr.task_done()
            if chunked:
                # get data
                # Less english knowledge make me hard to implement this chunked algortihm :(
                # I spend time to implement this
                chunkdata += item
                #print repr(chunkdata)
                #print repr(item), len(item)
                #continue
                if chunklen == None:
                    match = re.match('[\w\d]+\r\n', chunkdata)
                    if match:
                        chunklen = int(match.group(0)[:-2],16)
                        chunkdata = chunkdata[match.end():]
                        #print ('New chunk size: %d'%len(chunkdata))
                        #print('Chunklen: %d (%s)'%(chunklen, match.group(0)[:-2]))
                
                while chunklen and len(chunkdata) >= chunklen:
                    data += chunkdata[:chunklen]
                    chunkdata = chunkdata[chunklen+2:]
                    #print ('Got %d chunk ! %d rest'%(chunklen, len(chunkdata)))
                    #print 'TMP:',repr(chunkdata)
                    match = re.match('[\w\d]+\r\n', chunkdata)
                    if match:
                        chunklen = int(match.group(0)[:-2],16)
                        chunkdata = chunkdata[match.end():]
                        #print ('New chunk size: %d'%len(chunkdata))
                        #print('Chunklen: %d'%chunklen)
                        if chunklen == 0:
                            # got data
                            print ('Got data')
                            decompressed_data = zlib.decompress(data, 16+zlib.MAX_WBITS)
                            #print repr(decompressed_data)
                            chunked = False
                            # replace https and send to client
                            result = re.sub('https://','http://',decompressed_data)
                            print result
                            s = StringIO.StringIO()
                            g = gzip.GzipFile(fileobj=s, mode='w')
                            g.write(result)
                            g.close()
                            gzipped_body = s.getvalue()

                            new_body = '%s\r\n%s\r\n0\r\n\r\n'%(hex(len(gzipped_body)).lstrip('0x'),gzipped_body)
                            # send to client
                            print('Sending BACK')
                            self.client.send(self.http_response.request_line)
                            print repr(self.http_response.request_line)
                            new_headers = self.http_response.headers
                            # replace
                            for modh in http_response_replace:
                                new_headers[modh] = http_response_replace[modh]
                                print modh,'replaced wtih', http_response_replace[modh]
                            new_headers = '\r\n'.join( [ x + ': ' + str(new_headers[x]) for x in new_headers ] )
                            new_headers += '\r\n\r\n'
                            self.client.send(new_headers)
                            print (new_headers)
                            #self.client.send(self.http_response.headers_str)
                            #print repr(self.http_response.headers_str)
                            self.client.send(new_body)
                            #print repr(new_body)
                            From = 'From %s:%d'%(self.conn.getpeername())
                            if self.save:
                                response = ''.join([self.http_response.request_line,self.http_response.headers_str,result,])
                                detailed = '%s\n%s\n%s\n%s\n%s\n'%('#'*32, From, '#'*32,response,'='*32)
                                f = open('pysock_result','ab')
                                f.write(detailed)
                                f.close()
                            # reset
                            self.http_response = ReadHTTP()
                            sent = False
                            chunked = False
                            data = ''
                            chunkdata = ''
                            host = None
                            chunklen = None
                            break
                
                    else:
                        print('Not match')
                        chunkdata = ''
                        chunklen = None
                        print ('no chunklen left')
                        break
                else:
                    print ('chunk data not enough: %d with chunklen: %d'%(len(chunkdata), chunklen))
                if chunklen == 0:
                    # got data
                    print ('Got data')
                    decompressed_data = zlib.decompress(data, 16+zlib.MAX_WBITS)
                   #print repr(decompressed_data)
                    chunked = False
                    # replace https and send to client
                    result = re.sub('https://','http://',decompressed_data)
                    print result
                    s = StringIO.StringIO()
                    g = gzip.GzipFile(fileobj=s, mode='w')
                    g.write(result)
                    g.close()
                    gzipped_body = s.getvalue()

                    new_body = '%s\r\n%s\r\n0\r\n\r\n'%(hex(len(gzipped_body)).lstrip('0x'),gzipped_body)
                    # send to client
                    print('Sending BACK')
                    self.client.send(self.http_response.request_line)
                    print repr(self.http_response.request_line)
                    new_headers = self.http_response.headers
                    # replace
                    for modh in http_response_replace:
                        new_headers[modh] = http_response_replace[modh]
                        print modh,'replaced wtih', http_response_replace[modh]
                    new_headers = '\r\n'.join( [ x + ': ' + str(new_headers[x]) for x in new_headers ] )
                    new_headers += '\r\n\r\n'
                    self.client.send(new_headers)
                    print (new_headers)
                    #self.client.send(self.http_response.headers_str)
                    #print repr(self.http_response.headers_str)
                    self.client.send(new_body)
                    #print repr(new_body)
                    From = 'From %s:%d'%(self.conn.getpeername())
                    if self.save:
                        response = ''.join([self.http_response.request_line,self.http_response.headers_str,result,])
                        detailed = '%s\n%s\n%s\n%s\n%s\n'%('#'*32, From, '#'*32,response,'='*32)
                        f = open('pysock_result','ab')
                        f.write(detailed)
                        f.close()
                    # reset
                    self.http_response = ReadHTTP()
                    sent = False
                    chunked = False
                    data = ''
                    chunkdata = ''
                    host = None
                    chunklen = None
                     #break
                continue
                        
            elif sent:
                # pkt already sent
                try:
                    self.client.send(item)
                except socket.error as e:
                    print ('Sending to client error: %r'%e)
                    return self.on_close()
                print repr(item)
                
                f = open('pysock_result','ab')
                f.write('~'*32+'\n'+item+'\n'+'~'*32+'\n')
                f.close()
                #self.qr.task_done()
                continue
            # let's take it into read_http
            HTTP = self.http_response.read_http(item)
            #self.qr.task_done()
            if self.http_response.headers_ok:
                
                try:
                    version, code, reason = self.http_response.request_line.strip().split(' ',2)
                except ValueError:
                    print 'Invalid response !'
                    print self.http_response.request_line
                    break
                #
                # check host
                if self.http_response.headers.has_key('location'):
                    print self.http_response.request_line
                    print self.http_response.headers_str
                    uri = self.http_response.headers['location'] #strip()
                    print 'NEW LOCATION:',uri
                    parsed_uri = urlparse.urlparse(uri)
                    host = parsed_uri.netloc
                    
                    if host:
                        if uri.startswith('https://'):
                            port = 443
                            sock = socket.socket()
                            context = ssl._create_unverified_context()   
                            conn = context.wrap_socket(sock)
                            try:
                                conn.connect((host,port))
                            except Exception as e:
                                print 'Host not found?',host,port
                                print 'HTTPS Sock Error',e
                                return self.on_close()
                        else:
                            port = 80
                            conn = socket.socket()
                            try:
                                conn.connect((host,port))
                            except Exception as e:
                                print 'Host not found?',host,port
                                print 'HTTP Sock Error',e
                                return self.on_close()
                    
                        self.inputs.remove(self.conn)
                        self.conn.close()
                        self.inputs.append(conn)
                        self.conn = conn
                        print('Connected HTTP(S) to %s:%d'%(host,port))
                    try:
                        method, req_uri, version = self.http_request.request_line.strip().split(' ',2)
                    except ValueError as e:
                        print 'Invalid request !'
                        print self.http_request.request_line
                        break
                    if not host:
                        # sometime just url path
                        pass
                        
                    req = ' '.join([method, uri, version ]) + '\r\n'
                    self.conn.send(req)
                    print repr(req)

                    new_headers = self.http_request.headers
                    # replace
                    for modh in http_request_replace:
                        new_headers[modh] = http_request_replace[modh]
                        print modh,'replaced wtih', http_request_replace[modh]

                    if host:
                        new_headers['host'] = host
                    
                    new_headers = '\r\n'.join( [ x + ': ' + str(new_headers[x]) for x in new_headers ] )
                    new_headers += '\r\n\r\n'
                    self.conn.send(new_headers)
                    print repr(new_headers)
                    msg = self.http_request.body
                    while msg:
                        msg = msg[self.conn.send(msg):]
                    print repr(self.http_request.body)
                    try:
                        From = 'From %s:%d'%(self.client.getpeername())
                    except:
                        return self.on_close()
                    if self.save:
                        request = ''.join([self.http_request.request_line.replace(req_uri, uri),new_headers,self.http_request.body,])
                        detailed = '%s\n%s\n%s\n%s\n%s\n'%('#'*32, From, '#'*32,request,'='*32)
                        f = open('pysock_result','ab')
                        f.write(detailed)
                        f.close()
                    # reset
                    self.http_response = ReadHTTP()
                    sent = False
                    chunked = False
                    data = ''
                    chunkdata = ''
                    host = None
                    chunklen = None
                else: 
                    print 'No Location'
                    if self.http_response.headers.has_key('content-length') and self.http_response.headers.has_key('content-type') and re.search('text/html', self.http_response.headers['content-type']):
                        # terima body hingga selesai
                        # lalu replace https dgn http
                        size = int(self.http_response.headers['content-length'])
                        tipe = self.http_response.headers['content-type']
                        if re.search('text/html', tipe):
                            size = int(size)
                            if len(self.http_response.body) == size:
                                # response selesai
                                body = re.sub('https://', 'http://',self.http_response.body)
                                self.client.send(self.http_response.request_line)
                                print repr(self.http_response.request_line)
                                new_headers = self.http_response.headers
                                
                                # replace
                                for modh in http_response_replace:
                                    new_headers[modh] = http_response_replace[modh]
                                    print modh,'replaced wtih', http_response_replace[modh]
                    
                                
                                new_headers['content-length'] = str(len(body))
                                new_headers = '\r\n'.join( [ x + ': ' + str(new_headers[x]) for x in new_headers ] )
                                new_headers += '\r\n\r\n'
                                self.client.send(new_headers)
                                print repr(new_headers)
                                msg = body
                                while msg:
                                    msg = msg[self.client.send(msg):]
                                #self.client.send(body)
                                print repr(body)
                                From = 'From %s:%d'%(self.conn.getpeername())
                                if self.save:
                                    response = ''.join([self.http_response.request_line,new_headers,body,])
                                    detailed = '%s\n%s\n%s\n%s\n%s\n'%('#'*32, From, '#'*32,response,'='*32)
                                    f = open('pysock_result','ab')
                                    f.write(detailed)
                                    f.close()
                            
                            continue
                    elif self.http_response.headers.has_key('transfer-encoding') and self.http_response.headers['transfer-encoding'] == 'chunked':
                        chunked = True
                        print '<chunked-data>'
                        #self.http_response.headers.has_key('content-encoding') and self.http_response.headers['content-encoding'] == 'gzip': 
                        # get data
                        #match = re.match('[\w\d]+\r\n', self.http_response.body)
                        #chunklen = int(self.http_response.body.splitlines()[0],16)
                        #chunklen = int(match.group(0).strip(),16)
                        chunkdata += self.http_response.body #[match.end():]
                        #print ('Chunklen : %d (%s)'%(chunklen, match.group(0).strip()))
                        #print repr(self.http_response.body)
                        continue
                    else:
                        print '[ ! ] Don\'t know how to parse response'
                        try:
                            self.client.send(self.http_response.request_line)
                            print repr(self.http_response.request_line)
                            #self.client.send(self.http_response.headers_str)
                            #print repr(self.http_response.headers_str)
                            new_headers = self.http_response.headers
                            # replace
                            for modh in http_response_replace:
                                new_headers[modh] = http_response_replace[modh]
                                print modh,'replaced wtih', http_response_replace[modh]
                                
                            new_headers = '\r\n'.join( [ x + ': ' + str(new_headers[x]) for x in new_headers ] )
                            new_headers += '\r\n\r\n'
                            self.client.send(new_headers)
                            print repr(new_headers)
                            self.client.send(self.http_response.body)
                            print repr(self.http_response.body)
                            sent = True
                            From = 'From %s:%d'%(self.conn.getpeername())
                            if self.save:
                                response = ''.join([self.http_response.request_line,self.http_response.headers_str,self.http_response.body,])
                                detailed = '%s\n%s\n%s\n%s\n%s\n'%('#'*32, From, '#'*32,response,'='*32)
                                f = open('pysock_result','ab')
                                f.write(detailed)
                                f.close()
                            self.http_response = ReadHTTP()
                            #sent = False
                            chunked = False
                            data = ''
                            chunkdata = ''
                            host = None
                            chunklen = None
                        except socket.error as e:
                            print ('Sending to client error: %r'%e)
                            return self.on_close()
                    #

        
    def handle(self):
        run = True
        if self.save:
            f = open('pysock_result','w')
            f.write('')
            f.close()
        
        self.conn = self.create_conn()
        self.inputs = [self.client]
        if self.direct:
            pass
        else:
            if not self.conn:
                return
            print 'SockServer:',self.conn
            self.inputs.append(self.conn)
        
        
        if self.http_mode:
            self.q = Queue()
            self.qr = Queue()
            t = threading.Thread(target=self.http_handler)
            t.daemon = True
            t.start()
            t = threading.Thread(target=self.shttp_handler)
            t.daemon = True
            t.start()
        while run:
            try:
                r,w,e = select.select(self.inputs, self.inputs, self.inputs)
            except:
                # Unexpected closed connection
                break
            if self.client in r:
                try:
                    request = self.client.recv(self.buff_send)
                except Exception as e:
                    print 'Error recving from Client',e
                    break
                if not request:
                    print 'No request'
                    break
                #print('#Request#')
                #print repr(request)
                if self.http_mode:
                    self.q.put(request)
                    continue
                try:
                    conn.send(request)
                except Exception as e:
                    print 'Error sending to Server',e
                    break
                
            if self.conn and self.conn in r:
                try:
                    response = self.conn.recv(self.buff_recv)
                except Exception as e:
                    print 'Error recving from Server',e
                    break
                if not response:
                    print 'No response', repr(response)
                    break
                if self.http_mode:
                    self.qr.put(response)
                    continue
                try:
                    self.client.send(response)
                except Exception as e:
                    print e
                    break
                
                #print('#Response#')
                #print repr(response)
                



class PySock(object):

    def __init__(self, lport=8190, handler=SockHandler):
        self.handler = handler
        self.s = socket.socket()
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        self.s.bind(('', lport))
        self.s.listen(0)
        print ('Running on port %d'%lport)
    
    def use_proxy(self, (host, port)):
        pass
    
    def main(self):
        run = True
        while run:
            client = self.s.accept()
            t = threading.Thread(target=self.handler, args=(client))
            t.daemon = True
            t.start()
    

class ReadHTTP:
    tmp = ''
    headers_ok = False
    request_ok = False
    request_line = ''
    headers = {}
    headers_str = ''
    body = ''
    def read_http(self, pkt):
        #pkt = u'%s'%(pkt).encode('utf-8')
        self.tmp += pkt
        req = self.tmp.splitlines(1)

        if len(req) <= 1:
            return
        for r in req:
            #print repr(r)
            if not self.request_ok:
                self.request_line += r
                self.request_ok = True
                continue

            elif not self.headers_ok:
                self.headers_str += r
                if not r.strip():
                    self.headers = mimetools.Message(StringIO.StringIO(self.headers_str.strip()))
                    self.headers_ok = True
                    continue
                
            else:
                self.body += r
        self.tmp = ''


class SomeHandler(SockHandler):
    pass

#SomeHandler.reverse_proxy = 'proxy',port
#SomeHandler.ssl_mode = 1
SomeHandler.save = True
SomeHandler.http_mode = True

if __name__ == '__main__':
    lport = 8090
    # get pkg if any
    pkg_name = None
    if len(sys.argv)>1:
        flush = '''#echo "'Flushing Rules"
iptables -t nat -p 6 -D OUTPUT --dport 80 -j PySock
iptables -t nat -F PySock
iptables -t nat -X PySock
'''    
        pkg_name = sys.argv[-1]
        # get uid
        uid = get_id(pkg_name)
        if os.getuid() != 0:
            sorry = 'Sorry !\nRedirection needs Root'
            raise Exception(sorry)
        rules = '''
        iptables -t nat -S PySock
        if [ $? = 0 ]; then
            %s
        fi
        iptables -t nat -N PySock
        iptables -t nat -A PySock -d 0.0.0.0/8 -j RETURN
        iptables -t nat -A PySock -d 10.0.0.0/8 -j RETURN
        iptables -t nat -A PySock -d 127.0.0.0/8 -j RETURN
        iptables -t nat -A PySock -d 169.254.0.0/16 -j RETURN
        iptables -t nat -A PySock -d 172.16.0.0/12 -j RETURN
        iptables -t nat -A PySock -d 192.168.0.0/16 -j RETURN
        iptables -t nat -A PySock -d 224.0.0.0/4 -j RETURN
        iptables -t nat -A PySock -d 240.0.0.0/4 -j RETURN  
        iptables -t nat -A PySock -p tcp -m owner --uid-owner %d  -j REDIRECT --to-ports %d
        iptables -t nat -p 6 -A OUTPUT --dport 80 -j PySock
        '''%(flush, uid, lport)
        #print rules
        os.popen(rules).close()
        print ('Redirected')
    p = PySock(handler=SomeHandler, lport=lport)
    try:
        p.main()
    except KeyboardInterrupt:
        if pkg_name:
            os.popen(flush).close()
