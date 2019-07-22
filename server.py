# -*- coding:utf-8 -*-
import socket
import select
import struct
import cPickle
import os
import time
import random
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


class Server(DataCipher):
    class SendHostInfo(object):
        def __init__(self):
            self.connID = None
            self.sendSoc = None
            self.sendData = None

    ########################################################################################
    def __init__(self, tunnelPort, userPort):
        super(Server, self).__init__()

        self.__tunnelPort = tunnelPort
        self.__userPort = userPort

        self.__listenTunnelSoc = None
        self.__listenUserSoc = None
        self.__conn_id_rand = 1

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
    def __init_tunnel_sock(self):
        try:
            self.__listenTunnelSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__listenTunnelSoc.bind(("0.0.0.0", self.__tunnelPort))
            self.__listenTunnelSoc.listen(1)
            print "[+] Listening tunnel port on %d ..." % (self.__tunnelPort)
        except Exception, e:
            print "[-] Bind tunnel port failed."
            os._exit(-1)

    ########################################################################################
    def __init_user_sock(self):
        try:
            self.__listenUserSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__listenUserSoc.bind(("0.0.0.0", self.__userPort))
            self.__listenUserSoc.listen(socket.SOMAXCONN)
            print "[+] Listening user port on %d ..." % (self.__userPort)
        except Exception, e:
            print "[-] Bind user port failed."
            os._exit(-1)

    ########################################################################################
    def __conn_auth(self):
        try:
            self.__tunnelSoc.settimeout(self.__tunnelSocTimeout)
            recvBuf = self.__tunnelSoc.recv(100)
            if recvBuf == self.__auth_key:
                cipherChr = chr(random.randint(50, 255))
                self.__tunnelSoc.send(cipherChr)
                self.__tunnelSoc.settimeout(None)
                self.set_encrypt_key(cipherChr)
                self.set_decrypt_key(cipherChr)
                print "[+] Authentication successful."
            else:
                print "[-] Authentication failed."
                raise Exception
        except Exception, e:
            raise e

        self.__tunnelRecvTimestamp = time.time()
        self.__tunnelSendTimestamp = time.time()
        self.set_tunnel_status(True)

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
    def __close_sock(self, sock):
        try:
            if sock:
                sock.close()
        except Exception, e:
            print e
        finally:
            return

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
    def __generate_conn_id(self):
        if len(self.__connList) >= 65535:
            raise Exception("The connection list is overflow.")

        if self.__connListMutex.acquire():
            while True:
                usedFlag = False
                for connElem in self.__connList:
                    if connElem.id == self.__conn_id_rand:
                        usedFlag = True
                        self.__conn_id_rand += 1
                        if self.__conn_id_rand > 65536:
                            self.__conn_id_rand = 1
                        break
                if not usedFlag:
                    break
        self.__connListMutex.release()

        self.__conn_id_rand += 1
        return self.__conn_id_rand - 1

    ########################################################################################
    def recv_event_handler(self, rdList):
        if self.__tunnelSoc and (time.time() - self.__tunnelRecvTimestamp > self.__tunnelAliveTimeout):
            print "[-] Tunnel timeout."
            self.set_tunnel_status(False)
            return

        for socElem in rdList:
            # accept from tunnel
            if socElem is self.__listenTunnelSoc and not self.__tunnelSoc:
                try:
                    (self.__tunnelSoc, self.__tunnelAddr) = socElem.accept()
                    self.__tunnelSoc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # disable nagle
                    print "[+] Accepted connection from %s:%d" % (self.__tunnelAddr[0], self.__tunnelAddr[1])
                except Exception, e:
                    print "[-] Accepted tunnel connection failed. Exception : %s" % (e)
                    return

                try:
                    self.__conn_auth()
                    print "[+] Build tunnel successful."
                except Exception, e:
                    self.__close_sock(self.__tunnelSoc)
                    self.__tunnelSoc = None
                    print "[-] This may be a rogue connection. Killed it!"
                    return

            # accept from user
            elif socElem is self.__listenUserSoc:
                try:
                    connInfo = ConnInfo()
                    (connInfo.soc, connInfo.addr) = socElem.accept()
                    connInfo.soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except Exception, e:
                    print "[-] Accepted user connection failed. Exception : %s" % (e)
                    continue

                if not self.__tunnelSoc:
                    connInfo.soc.close()
                    continue

                try:
                    connInfo.id = self.__generate_conn_id()
                except Exception, e:
                    self.__close_sock(connInfo.soc)
                    print "[-] Generate connection id failed. Exception : %s" % (e)
                    continue
                self.__add_user_conn(connInfo)

                try:
                    sendTunnelData = TunnelProto()
                    sendTunnelData.type = "connect"
                    sendTunnelData.id = connInfo.id
                    self.__add_tunnel_send_queue(sendTunnelData)
                    print "[+] \"%s:%d\" is connected. ID: %d" % (connInfo.addr[0],
                                                                  connInfo.addr[1], connInfo.id)
                except Exception, e:
                    print "[-] Broken tunnel. Exception : %s" % (e)
                    self.set_tunnel_status(False)
                    return

            # recv from tunnel
            elif socElem is self.__tunnelSoc:
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
                    if recvTunnelData.type != "keep_alive":
                        recvConnInfo = self.__get_conn_elem(recvTunnelData.id)
                        if recvConnInfo is None:
                            print "[-] Not found connection ID : %d" % (recvTunnelData.id)
                            continue

                    if recvTunnelData.type == "close_socket":
                        try:
                            self.__pop_user_conn(recvConnInfo.id)
                        except Exception, e:
                            raise e
                    elif recvTunnelData.type == "mapping":
                        self.__add_host_send_queue(recvTunnelData.id, recvConnInfo.soc, recvTunnelData.rawData)
                    elif recvTunnelData.type == "keep_alive":
                        self.__add_tunnel_send_queue(recvTunnelData)
                except Exception, e:
                    raise e

            # recv from user
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
            rdSet = []
            if self.__listenUserSoc:
                rdSet.append(self.__listenUserSoc)
            if self.__tunnelSoc:
                rdSet.append(self.__tunnelSoc)
            else:
                rdSet.append(self.__listenTunnelSoc)

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
        self.__init_tunnel_sock()
        self.__init_user_sock()

        self.start_send_thread()
        self.recv_event_monitor()


if __name__ == '__main__':
    servlet = Server(8099, 8091)
    servlet.start_service()