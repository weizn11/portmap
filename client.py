# -*- coding:utf-8 -*-
import socket
import select
import struct
import cPickle
import time
import threading
import Queue

class TunnelProto(object):
    def __init__(self):
        self.type = None
        self.id = None
        self.rawData = None

class ConnInfo(object):
    def __init__(self):
        self.soc = None
        self.addr = None
        self.id = None

class DataCipher(object):
    def __init__(self):
        super(DataCipher, self).__init__()
        self.enKey = None
        self.deKey = None

    ########################################################################################
    def encrypt(self, str):
        if not self.enKey:
            raise Exception("The encrypt key is not set.")
        newStr = ""
        for ch in str:
            newStr += chr(ord(ch) ^ ord(self.enKey))
        return newStr

    ########################################################################################
    def decrypt(self, str):
        if not self.deKey:
            raise Exception("The decrypt key is not set.")
        newStr = ""
        for ch in str:
            newStr += chr(ord(ch) ^ ord(self.deKey))
        return newStr

    ########################################################################################
    def set_encrypt_key(self, key):
        self.enKey = key

    def set_decrypt_key(self, key):
        self.deKey = key

class TunnelSendThread(threading.Thread):
    def __init__(self, clientQuote):
        super(TunnelSendThread, self).__init__()
        self.__clientQuote = clientQuote

    ########################################################################################
    def run(self):
        if not self.__clientQuote:
            raise Exception("Subclass quote not set.")
        while True:
            try:
                sendData = self.__clientQuote.tunnelSendQueue.get(block=True, timeout=5)
            except Exception, e:
                continue

            if not self.__clientQuote.get_tunnel_status():
                continue

            try:
                self.__clientQuote.tunnel_send(sendData)
            except Exception, e:
                print "[-] Broken tunnel. Exception : %s" % (e)
                self.__clientQuote.set_tunnel_status(False)

class HostSendThread(threading.Thread):
    def __init__(self, clientQuote):
        super(HostSendThread, self).__init__()
        self.__clientQuote = clientQuote
        self.__sendSocTimeout = 15

    ########################################################################################
    def run(self):
        if not self.__clientQuote:
            raise Exception("Subclass quote not set.")

        while True:
            try:
                sendElem = self.__clientQuote.hostSendQueue.get(block=True, timeout=5)
            except Exception, e:
                continue

            if not self.__clientQuote.get_tunnel_status():
                continue

            try:
                sendElem.sendSoc.settimeout(self.__sendSocTimeout)
                sendElem.sendSoc.send(sendElem.sendData)
                sendElem.sendSoc.settimeout(None)
            except Exception, e:
                if not self.__clientQuote.get_tunnel_status():
                    continue
                self.__clientQuote.clean_user_conn(sendElem.connID)

class Client(DataCipher):
    class SendHostInfo(object):
        def __init__(self):
            self.connID = None
            self.sendSoc = None
            self.sendData = None

    ########################################################################################
    def __init__(self, servHost, servPort, tarHost, tarPort):
        super(Client, self).__init__()

        self.__servHost = servHost
        self.__servPort = servPort
        self.__tarHost = tarHost
        self.__tarPort = tarPort

        self.__tunnelSoc = None
        self.__tunnelAddr = None

        self.__connList = []
        self.__connListMutex = threading.Lock()

        self.__auth_key = "SGVsbG8gV29yZCE="

        self.__tunnelRecvHdr = True
        self.__tunnelRecvLength = None
        self.__tunnelRecvBuf = None

        self.__tunnelSocTimeout = 15
        self.__tunnelAliveSendSpac = 5
        self.__tunnelAliveTimeout = 15
        self.__hostConnTimeout = 5
        self.__tunnelRecvTimestamp = 0
        self.__tunnelSendTimestamp = 0

        self.__tunnelStatus = True
        self.__tunnelStatusMutex = threading.Lock()

        self.tunnelSendQueue = Queue.Queue(maxsize=0)
        self.hostSendQueue = Queue.Queue(maxsize=0)

        self.__tunnelSendThread = TunnelSendThread(self)
        self.__hostSendThread = HostSendThread(self)

    ########################################################################################
    def __conn_auth(self):
        try:
            self.__tunnelSoc.send(self.__auth_key)
            cipherChr = self.__tunnelSoc.recv(1)
            if len(cipherChr) == 0:
                print "[-] Authentication failed."
                return
        except Exception, e:
            print "[-] Authentication failed."
            return
        self.set_encrypt_key(cipherChr)
        self.set_decrypt_key(cipherChr)

    ########################################################################################
    def __connect_to_serv(self):
        while True:
            try:
                self.__tunnelSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.__tunnelSoc.settimeout(self.__tunnelSocTimeout)
                self.__tunnelSoc.connect((self.__servHost, self.__servPort))
                self.__conn_auth()
                self.__tunnelSoc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.__tunnelSoc.settimeout(None)
                self.__tunnelRecvTimestamp = time.time()
                self.__tunnelSendTimestamp = time.time()
                self.set_tunnel_status(True)
                print "[+] Authentication successful."
                print "[+] Build tunnel successful."
                break
            except Exception, e:
                print "[-] Can't connect to server. I will retry..."
                self.__close_sock(self.__tunnelSoc)
                time.sleep(5)

    ########################################################################################
    def __close_sock(self, sock):
        try:
            if sock:
                sock.close()
        except Exception, e:
            print e
        finally:
            return

    ########################################################################################
    def set_tunnel_status(self, tunnelStatus):
        if self.__tunnelStatusMutex.acquire():
            self.__tunnelStatus = tunnelStatus
            self.__tunnelStatusMutex.release()

    ########################################################################################
    def get_tunnel_status(self):
        retVal = None
        if self.__tunnelStatusMutex.acquire():
            retVal = self.__tunnelStatus
            self.__tunnelStatusMutex.release()
        return retVal

    ########################################################################################
    def tunnel_recv(self):
        try:
            if self.__tunnelRecvBuf is None:
                self.__tunnelRecvBuf = ""
            if self.__tunnelRecvHdr and self.__tunnelRecvLength is None:
                self.__tunnelRecvLength = 4

            if self.__tunnelRecvLength != 0:
                chunk = self.__tunnelSoc.recv(self.__tunnelRecvLength)
                if len(chunk) == 0:
                    raise Exception("Connection closed by foreign host.")
                self.__tunnelRecvBuf += chunk
                self.__tunnelRecvLength -= len(chunk)
        except Exception, e:
            raise e

        try:
            if self.__tunnelRecvHdr and self.__tunnelRecvLength == 0:
                self.__tunnelRecvLength = struct.unpack("<I", self.__tunnelRecvBuf)[0]
                if self.__tunnelRecvLength == 0 or self.__tunnelRecvLength >= 35000:
                    raise Exception("The next packet length is %d" % (self.__tunnelRecvLength))
                self.__tunnelRecvHdr = False
                self.__tunnelRecvBuf = None
            elif not self.__tunnelRecvHdr and self.__tunnelRecvLength == 0:
                data = self.decrypt(self.__tunnelRecvBuf)
                objData = cPickle.loads(data)
                self.__tunnelRecvHdr = True
                self.__tunnelRecvBuf = None
                self.__tunnelRecvLength = None
                if objData is None:
                    raise Exception("Deserialization failed.")
                self.__tunnelRecvTimestamp = time.time()
                return objData
        except Exception, e:
            raise e

        return None

    ########################################################################################
    def tunnel_send(self, tunnelData):
        self.__tunnelSoc.settimeout(self.__tunnelSocTimeout)
        try:
            rawData = cPickle.dumps(tunnelData, protocol=2)
            rawData = self.encrypt(rawData)
            rawData = struct.pack("<I", len(rawData)) + rawData
            self.__tunnelSoc.send(rawData)
        except Exception, e:
            self.__tunnelSoc.settimeout(None)
            raise e
        self.__tunnelSoc.settimeout(None)
        self.__tunnelSendTimestamp = time.time()

    ########################################################################################
    def __add_user_conn(self, connInfo):
        if self.__connListMutex.acquire():
            self.__connList.append(connInfo)
            self.__connListMutex.release()

    ########################################################################################
    def __get_conn_elem(self, connID):
        if self.__connListMutex.acquire():
            for index in range(0, len(self.__connList)):
                if self.__connList[index].id == connID:
                    self.__connListMutex.release()
                    return self.__connList[index]
        self.__connListMutex.release()
        return None

    ########################################################################################
    def __clean_all_conn(self):
        try:
            if self.__tunnelSoc:
                self.__close_sock(self.__tunnelSoc)
        except Exception, e:
            print "[-] Closed tunnel socket exception : %s" % (e)

        self.__tunnelSoc = None
        self.__tunnelAddr = None
        self.__tunnelRecvHdr = True
        self.__tunnelRecvLength = None
        self.__tunnelRecvBuf = None

        self.set_encrypt_key(None)
        self.set_decrypt_key(None)

        if self.__connListMutex.acquire():
            for connElem in self.__connList:
                self.__close_sock(connElem.soc)
            self.__connList = []
            self.__connListMutex.release()

        self.tunnelSendQueue.queue.clear()
        self.hostSendQueue.queue.clear()

        self.set_tunnel_status(True)
        print "[-] Clean up all connections.\n"

    ########################################################################################
    def __pop_user_conn(self, connID):
        def __get_conn_index(connID):
            for index in range(0, len(self.__connList)):
                if self.__connList[index].id == connID:
                    return index
            return -1

        if self.__connListMutex.acquire():
            index = __get_conn_index(connID)
            if index == -1:
                self.__connListMutex.release()
                raise Exception("Not found element in connection list. ID : %d." % (connID))

            self.__close_sock(self.__connList[index].soc)
            print "[-] \"%s:%d\" is disconnected. ID: %d" % (self.__connList[index].addr[0],
                                                             self.__connList[index].addr[1], connID)
            self.__connList.pop(index)
            self.__connListMutex.release()

    ########################################################################################
    def clean_user_conn(self, connID):
        sendTunnelData = TunnelProto()
        sendTunnelData.type = "close_socket"
        sendTunnelData.id = connID

        self.__add_tunnel_send_queue(sendTunnelData)

        try:
            self.__pop_user_conn(connID)
        except Exception, e:
            print "[-] Clean user connection failed. Exception : %s" % (e)

    ########################################################################################
    def __add_tunnel_send_queue(self, sendData):
        self.tunnelSendQueue.put(sendData)

    ########################################################################################
    def __add_host_send_queue(self, connID, sendSoc, sendData):
        sendInfo = self.SendHostInfo()
        sendInfo.connID = connID
        sendInfo.sendSoc = sendSoc
        sendInfo.sendData = sendData

        self.hostSendQueue.put(sendInfo)

    ########################################################################################
    def recv_event_handler(self, rdList):
        if self.__tunnelSoc and (time.time() - self.__tunnelSendTimestamp > self.__tunnelAliveSendSpac):
            sendTunnelData = TunnelProto()
            sendTunnelData.type = "keep_alive"
            self.__add_tunnel_send_queue(sendTunnelData)
            print "send keep_alive"

        if self.__tunnelSoc and (time.time() - self.__tunnelRecvTimestamp > self.__tunnelAliveTimeout):
            print "[-] Tunnel timeout."
            self.set_tunnel_status(False)
            return

        for socElem in rdList:
            # recv from tunnel
            if socElem is self.__tunnelSoc:
                try:
                    try:
                        recvTunnelData = self.tunnel_recv()
                        if recvTunnelData is None:
                            continue
                    except Exception, e:
                        print "[-] Broken tunnel. Exception : %s" % (e)
                        self.set_tunnel_status(False)
                        return

                    recvConnInfo = None
                    if recvTunnelData.type != "connect" and recvTunnelData.type != "keep_alive":
                        recvConnInfo = self.__get_conn_elem(recvTunnelData.id)
                        if recvConnInfo is None:
                            print "[-] Not found connection ID : %d" % (recvTunnelData.id)
                            continue

                    if recvTunnelData.type == "close_socket":
                        try:
                            self.__pop_user_conn(recvConnInfo.id)
                        except Exception, e:
                            raise e
                    elif recvTunnelData.type == "connect":
                        try:
                            newConn = ConnInfo()
                            (family, socktype, proto, canonname, sockaddr) = \
                                socket.getaddrinfo(self.__tarHost, self.__tarPort)[0]
                            newConn.soc = socket.socket(family, socket.SOCK_STREAM)

                            newConn.addr = sockaddr
                            newConn.id = recvTunnelData.id
                            self.__add_user_conn(newConn)
                            newConn.soc.settimeout(self.__hostConnTimeout)
                            newConn.soc.connect((self.__tarHost, self.__tarPort))
                            newConn.soc.settimeout(None)
                            newConn.soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                            print "[+] Connected to \"%s:%d\". ID: %d" % (newConn.addr[0],
                                                                          newConn.addr[1], recvTunnelData.id)
                        except Exception, e:
                            print "[-] Can't connect to \"%s:%d\". ID: %d" % (newConn.addr[0],
                                                                              newConn.addr[1], recvTunnelData.id)
                            self.clean_user_conn(recvTunnelData.id)
                    elif recvTunnelData.type == "mapping":
                        self.__add_host_send_queue(recvTunnelData.id, recvConnInfo.soc, recvTunnelData.rawData)
                    elif recvTunnelData.type == "keep_alive":
                        print "recv keep_alive"
                except Exception, e:
                    raise e

            # recv from target host
            else:
                findConnElem = False
                if self.__connListMutex.acquire():
                    for connElem in self.__connList:
                        if socElem is connElem.soc:
                            self.__connListMutex.release()

                            findConnElem = True
                            sendTunnelData = TunnelProto()
                            try:
                                sendTunnelData.type = "mapping"
                                sendTunnelData.id = connElem.id
                                sendTunnelData.rawData = socElem.recv(30000)
                                if len(sendTunnelData.rawData) == 0:
                                    self.clean_user_conn(connElem.id)
                                    break
                            except Exception, e:
                                self.clean_user_conn(connElem.id)
                                break

                            self.__add_tunnel_send_queue(sendTunnelData)
                            break
                if not findConnElem:
                    self.__connListMutex.release()

    ########################################################################################
    def recv_event_monitor(self):
        while True:
            if not self.__tunnelSoc:
                self.__connect_to_serv()

            rdSet = []
            if self.__tunnelSoc:
                rdSet.append(self.__tunnelSoc)

            if self.__connListMutex.acquire():
                for connElem in self.__connList:
                    rdSet.append(connElem.soc)
                self.__connListMutex.release()

            rdList, wrList, errList = select.select(rdSet, [], [], 0.001)

            try:
                self.recv_event_handler(rdList)
            except Exception, e:
                print "[-] recv_event_handler() exception : %s" % (e)
                self.set_tunnel_status(False)

            if not self.get_tunnel_status():
                self.__clean_all_conn()

    ########################################################################################
    def start_send_thread(self):
        self.__tunnelSendThread.start()
        self.__hostSendThread.start()

    ########################################################################################
    def start_service(self):
        self.start_send_thread()
        self.recv_event_monitor()

if __name__ == '__main__':
    client = Client("61.178.30.184", 8099, "127.0.0.1", 3389)
    client.start_service()

