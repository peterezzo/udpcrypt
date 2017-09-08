#!/usr/bin/env python
#  coding=utf-8
"""
Server Application

* Communicates over UDP
* Packet payload AES encrypted by key SHA-256 hashed


"""

from __future__ import division, print_function, unicode_literals

import base64
import json
import logging
import os
import socket
import time

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class JsonParseError(Exception):
    pass


class Clients(object):
    __slots__ = ('sock', 'password', 'hbthreshold', 'clients', 'communities')

    def __init__(self, configfile=None):
        # get info from json
        configpath = configfile or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'serverconfig.json')
        try:
            with open(configpath) as configfile:
                config = json.load(configfile)
        except (EnvironmentError, ValueError):
            raise JsonParseError('Failed to find or parse config file')

        # set up UDP listener
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(60)
        self.sock.bind((config['bindIp'], config['bindPort']))

        self.password = config['serverKey']
        self.hbthreshold = config['heartbeatThreshold']
        self.clients = {}
        self.communities = {}

    def add(self, addr, salt):
        logging.info('Generating encryption key for {}'.format(addr[0]))
        self.clients[addr[0]] = Client(self.sock, addr, salt, self.password)

    def remove(self, client):
        raise NotImplementedError

    def addtocomm(self, community, addr):
        logging.info('Adding host {} to community {}'.format(addr[0], community))
        client = self.clients[addr[0]]
        if self.communities[community]:
            self.communities[community].add(client)
            if client.getmapping():
                self.communities[community].refresh()
        else:
            newcommunity = Community()
            newcommunity.add(client)
            self.communities[community] = newcommunity

    def addmapping(self, wanip, greip, addr):
        logging.info('Processing mapping of {} to {} for {}'.format(greip, wanip, addr[0]))
        self.clients[addr[0]].addmapping(wanip, greip)

    def sendto(self, message, addr):
        self.clients[addr[0]].sendto(message)

    def recvfrom(self, buffersize=1024):
        rdata, addr = self.sock.recvfrom(buffersize)
        return rdata, addr

    def decrypt(self, message, addr):
        return self.clients[addr[0]].decrypt(message)


class Community(object):
    __slots__ = 'members'

    def __init__(self):
        self.members = set()

    def __contains__(self, item):
        return item in self.members

    def add(self, client):
        self.members.add(client)

    def remove(self, client):
        self.members.remove(client)

    def sendto(self, message):
        for client in self.members:
            client.sendto(message)

    def refresh(self):
        mappings = []
        for client in self.members:
            mappings.append(client.getmapping())

        # breadth vs depth ?
        self.sendto('MAP_ALL_{}'.format(len(mappings)))
        for index in range(len(mappings)):
            self.sendto('MAP_{}_{}_{}'.format(index, mappings[index][0], mappings[index][1]))


class Client(object):
    __slots__ = ('state', 'sock', 'addr', 'greip', 'wanip', 'lastseen', 'lastsent', 'f')

    def __init__(self, sock, addr, salt, password):
        self.sock = sock
        self.addr = addr
        self.greip = None
        self.wanip = None
        self.lastseen = time.time()
        self.lastsent = time.time()

        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))

        self.f = Fernet(key)

    def sendto(self, message):
        self.lastsent = time.time()
        self.sock.sendto(self.f.encrypt(message.encode('utf-8')), self.addr)

    def decrypt(self, message):
        self.lastseen = time.time()
        return self.f.decrypt(message).decode('utf-8')

    def addmapping(self, wanip, greip):
        self.greip = greip
        self.wanip = wanip

    def getmapping(self):
        return self.wanip, self.greip


def main():
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', level=logging.INFO)

    clients = Clients()

    while True:
        try:
            rdata, addr = clients.recvfrom(4096)
        except socket.timeout:
            continue

        try:
            message = clients.decrypt(rdata, addr)
        except (KeyError, InvalidToken):
            # received a packet from a host not set up or an encrypted packet we couldn't decrypt
            logging.warning('Received undecryptable packet from host {}'.format(addr[0]))
            umessage = rdata.decode('utf-8')

            # only untrusted packet we accept is REG_REQ
            if 'REG_REQ_' in umessage:
                logging.info('Received reg message')
                # new client requesting join, packet is REG_REQ_encodedsalt
                salt = base64.urlsafe_b64decode(umessage[8:].encode('utf-8'))

                clients.add(addr, salt)
                clients.sendto('REG_ACK', addr)

            continue

        if '' == message:
            # recv timeout
            continue

        elif 'REG_MAP_' in message:
            # REG_MAP_$wanip$_$greip$
            # SC: REG_MAP_ACK
            # SoC1: MAP_ADD_$wanip$_$greip$
            # SoC2: MAP_ADD_$wanip$_$greip$
            # SoCn: ...
            rawmap = message[8:].split('_')
            clients.addmapping(rawmap[0], rawmap[1], addr)

        elif 'REG_JOIN_' in message:
            # CS: REG_JOIN_$community$
            # SC: REG_JOIN_ACK
            community = message[8:]
            clients.addtocomm(community, addr)
            clients.sendto('REG_JOIN_ACK', addr)

        elif 'COMM_REFRESH' == message:
            # SC: MAP_ALL_$membercount$
            # SC: MAP_$index0$_$wanip$_$greip$
            # SC: MAP_$index1$_$wanip$_$greip$
            # SC: MAP_$indexn...
            pass

        elif 'PING' == message:
            clients.sendto('PONG', addr)

        elif 'PONG' == message:
            pass

        else:
            logging.warning('Unknown message from client: {}'.format(message))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
