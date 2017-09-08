#!/usr/bin/env python
# coding=utf-8

from __future__ import print_function, unicode_literals


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


class Server(object):
    __slots__ = ('sock', 'phase', 'addr', 'f', 'hbtime', 'password', 'keystart', 'keylifetime', 'lastseen', 'lastsent')

    def __init__(self, configfile=None):
        """
        Set up communication with a server
        
        :param unicode configfile: path to extra config file
        
        This object automatically manages configuration with a server through the setup phases
        Phase list:
            0: No communication
            1: Key has been generated
            2: Key has been accepted by server
        """

        # get info from json
        configpath = configfile or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clientconfig.json')
        try:
            with open(configpath) as configfile:
                config = json.load(configfile)
        except (EnvironmentError, ValueError):
            raise JsonParseError('Failed to find or parse configfile')

        # set up UDP listener
        self.addr = (config['serverIp'], config['serverPort'])
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(60)

        self.phase = 0
        self.keystart = 0
        self.hbtime = config['heartbeatThreshold']
        self.keylifetime = config['keyLifetime']
        self.password = config['serverKey']

        self.lastseen = time.time()
        self.lastsent = time.time()

        self.f = None

    def sendto(self, message):
        """
        Sends an encrypted message to the server associated with this object
        
        :param unicode message: Payload of the message to send
        :return: 
        """
        if self.phase < 2:
            raise ValueError('Unexpected sendto while connection not initialized')
        self.lastsent = time.time()
        logging.info('sending at {}'.format(self.lastsent))
        self.sock.sendto(self.f.encrypt(message.encode('utf-8')), self.addr)

    def decrypt(self, message):
        """
        Decrypt a message from the server with this object's key
        
        :param bytes message: A bytes object payload from remote peer
        :return: Decrypted message
        :rtype: unicode
        """
        self.lastseen = time.time()
        try:
            logging.info('decrypting at {}'.format(self.lastseen))
            return self.f.decrypt(message).decode('utf-8')
        except InvalidToken:
            logging.error('Decryption failure from server {} resetting state')
            self.phase = 1
            return ''

    def recvfrom(self, buffersize=1024, trapexception=True):
        """
        Listen for a message 
        
        :param buffersize: The socket object buffersize
        :param bool trapexception: Trap exception or send it back up to caller
        :return: Packet payload
        :rtype: bytes
        """
        try:
            rdata, addr = self.sock.recvfrom(buffersize)
            if addr != self.addr:
                rdata = ''.encode('utf-8')
        except socket.timeout:
            if trapexception:
                rdata = ''.encode('utf-8')
            else:
                raise
        return rdata

    def setup(self):
        """
        Manage key exchange with server and block until a key is confirmed
        
        :return: 
        """
        now = time.time()

        # key rotation
        if self.phase == 2 and now - self.keystart > self.keylifetime:
            self._build_sa('REKEY')

        # beaconing
        if now - self.lastseen > self.hbtime * 5:
            logging.warning('Server heartbeat timeout for {}'.format(self.addr[0]))
            self.phase = 1
        elif now - self.lastseen > self.hbtime and now - self.lastsent > self.hbtime:
            self.sendto('PING')

        # connection establishment
        while self.phase < 2:
            self._build_sa('REG')

    def _build_sa(self, operation):
        """
        Establish or re-establish a key with the server for this object
        
        :param unicode operation: Type to ask server for, either REG or REKEY
        :return: 
        """
        self.phase = 1

        salt = os.urandom(16)

        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password.encode('utf-8')))

        self.f = Fernet(key)

        message = '{}_REQ_{}'.format(operation, base64.urlsafe_b64encode(salt)).encode('utf-8')
        if operation == 'REG':
            self.sock.sendto(message.encode('utf-8'), self.addr)
        elif operation == 'REKEY':
            self.sock.sendto(self.f.encrypt(message.encode('utf-8')), self.addr)
        else:
            raise ValueError('Operation can only be REG or REKEY')
        self.lastsent = time.time()

        rdata = self.recvfrom(4096)

        try:
            message = self.f.decrypt(rdata).decode('utf-8')
            if message == '{}_ACK'.format(operation):
                self.phase = 2
                self.lastseen = time.time()
                logging.info('Established connection to server at {}'.format(self.addr[0]))

        except (InvalidToken, TypeError):
            logging.warning('Failed to establish connection to server at {}'.format(self.addr[0]))
            time.sleep(30)


def main():
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', level=logging.INFO)

    server = Server()

    while True:
        # SETUP phase of loop
        server.setup()

        # SEND phase of loop
        # server.sendto(getlocalmapping())

        # LISTEN phase of loop
        try:
            rdata = server.recvfrom(4096, trapexception=False)
        except socket.timeout:
            continue
        message = server.decrypt(rdata)

        if 'PING' == message:
            server.sendto('PONG')
        if 'PONG' == message:
            pass
        else:
            logging.warning('Unknown message from server: {}'.format(message))

        time.sleep(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
