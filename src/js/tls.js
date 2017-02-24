/* Copyright 2017-present Samsung Electronics Co., Ltd. and other contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



var util = require('util');
var net = require('net');
var console = require('console');
var tlsBuiltin = process.binding(process.binding.tls);



//// TlsError

function TlsError(msg) {
    this.name = 'TlsError';
    this.message = msg;
}



//////// ======== Server ========

function Server() {
    //TODO: Not implemented
}

// Server inherits net.Server.
//util.inherits(Server, net.Server);

//Event: 'tlsClientError'
//Event: 'newSession'
//Event: 'OCSPRequest'
//Event: 'resumeSession'
//Event: 'secureConnection'

// server.addContext(hostname, context)
Server.prototype.addContext = function(hostname, context) {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}

// server.address()
Server.prototype.address = function() {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}

// server.close([callback])
// [1] server.close()
// [2] server.close(callback)
Server.prototype.close = function(callback) {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}

// server.connections
Server.prototype.connections = 0;

// server.getTicketKeys()
Server.prototype.getTicketKeys = function() {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}

// server.listen(port[, hostname][, callback])
// [1] server.listen(port)
// [2] server.listen(port, hostname)
// [3] server.listen(port, callback)
// [4] server.listen(port, hostname, callback)
Server.prototype.listen = function(arg1, arg2, arg3) {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}

// server.setTicketKeys(keys)
Server.prototype.setTicketKeys = function(keys) {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}



//////// ======== TLSSocket ========

// new TLSSocket(socket[, options])
// [1] TLSSocket(socket)
// [2] TLSSocket(socket, options)
function TLSSocket(socket, options) {
    //TODO: Not implemented
}

// Socket inherits net.Socket.
//util.inherits(Socket, net.Socket);


//Event: 'OCSPResponse'
//Event: 'secureConnect'

// tlsSocket.address()
TLSSocket.prototype.address = function() {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}

// tlsSocket.authorized
TLSSocket.prototype.authorized = false;

// tlsSocket.authorizationError
TLSSocket.prototype.authorizationError = '';

// tlsSocket.encrypted
TLSSocket.prototype.encrypted = true;

// tlsSocket.localAddress
TLSSocket.prototype.localAddress = '';

// tlsSocket.localPort
TLSSocket.prototype.localPort = 0;

// tlsSocket.remoteAddress
TLSSocket.prototype.remoteAddress = '';

// tlsSocket.remoteFamily
TLSSocket.prototype.remoteFamily = '';

// tlsSocket.remotePort
TLSSocket.prototype.remotePort = 0;

// tlsSocket.getCipher()
TLSSocket.prototype.getCipher = function() {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}

// tlsSocket.getEphemeralKeyInfo()
TLSSocket.prototype.getEphemeralKeyInfo = function() {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}

// tlsSocket.getPeerCertificate([ detailed ])
// [1] tlsSocket.getPeerCertificate()
// [2] tlsSocket.getPeerCertificate(detailed)
TLSSocket.prototype.getPeerCertificate = function(detailed) {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}

// tlsSocket.getProtocol()
TLSSocket.prototype.getProtocol = function() {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}

// tlsSocket.getSession()
TLSSocket.prototype.getSession = function() {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}

// tlsSocket.getTLSTicket()
TLSSocket.prototype.getTLSTicket = function() {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}

// tlsSocket.renegotiate(options, callback)
TLSSocket.prototype.renegotiate = function(options, callback) {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}

// tlsSocket.setMaxSendFragment(size)
TLSSocket.prototype.setMaxSendFragment = function(size) {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}



//////// ======== Tls ========

function Tls() {
    //TODO: Not implemented
}


Tls.prototype.test = function() {
    tlsBuiltin.test();
};

// tls.connect(port[, host][, options][, callback])
// tls.connect(path[, options][, callback])
// tls.connect(options[, callback])
// [1] tls.connect(port)
// [2] tls.connect(port, host)
// [3] tls.connect(port, host, options)
// [4] tls.connect(port, host, options, callback)
// [5] tls.connect(path)
// [6] tls.connect(path, options)
// [7] tls.connect(path, options, callback)
// [8] tls.connect(options)
// [9] tls.connect(options, callback)
Tls.prototype.connect = function(arg1, arg2, arg3, arg4) {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}

// tls.createSecureContext(options)
Tls.prototype.createSecureContext = function(options) {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}

// tls.createServer([options][, secureConnectionListener])
// [1] tls.createServer(options)
// [2] tls.createServer(secureConnectionListener)
// [3] tls.createServer(options, secureConnectionListener)
Tls.prototype.createServer = function(arg1, arg2) {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}

// tls.getCliphers()
Tls.prototype.getCliphers = function() {
    //TODO: Not implemented
    throw new TlsError('Not implemented');
}

Tls.prototype.DEFAULT_ECDH_CURVE = 'prime256v1';

module.exports = new Tls();
module.exports.Tls = Tls;

//////// ======== Deprecated API ========

// Class: CryptoStream
    // cryptoStream.bytesWritten

// Class: SecurePair
    // Event: 'secure'

// tls.createSecurePair([context][, isServer][, requestCert][, rejectUnauthorized][, options])

