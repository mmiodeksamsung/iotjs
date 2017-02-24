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
var tls = require('tls');
var http = require('http');
var console = require('console');
//var httpsBuiltin = process.binding(process.binding.https);



//// HttpsError

function HttpsError(msg) {
    this.name = 'HttpsError';
    this.message = msg;
}



//////// ======== Agent ========

function Agent() {
    //TODO: Not implemented
}

// Agent inherits http.Agent.
//util.inherits(Agent, http.Agent);




//////// ======== Server ========

function Server() {
    //TODO: Not implemented
}

// Server inherits tls.Server.
//util.inherits(Server, tls.Server);

// server.setTimeout(msecs, callback)
Server.prototype.setTimeout = function(msecs, callback) {
    //TODO: Not implemented
    throw new HttpsError('Not implemented');
}

// server.timeout
Server.prototype.timeout = 120000; // 2 minutes

// server.close([callback])
// [1] server.close()
// [2] server.close(callback)
Server.prototype.close = function(callback) {
    //TODO: Not implemented
    throw new HttpsError('Not implemented');
}

// server.listen(handle[, callback])
// server.listen(path[, callback])
// server.listen(port[, host][, backlog][, callback])
Server.prototype.listen = function(arg1, arg2, arg3, arg4) {
    //TODO: Not implemented
    throw new HttpsError('Not implemented');
}



//////// ======== Https ========

function Https() {
    //TODO: Not implemented
}

Https.prototype.test = function() {
    console.log('Https.test();');
}

// https.createServer(options[, requestListener])
// [1] https.createServer(options)
// [2] https.createServer(options, requestListener)
Https.prototype.createServer = function(options, requestListener) {
    //TODO: Not implemented
    throw new HttpsError('Not implemented');
}

// https.get(options, callback)
Https.prototype.get = function(options, callback) {
    //TODO: Not implemented
    throw new HttpsError('Not implemented');
}

// https.globalAgent

// https.request(options, callback)
Https.prototype.request = function(options, callback) {
    //TODO: Not implemented
    throw new HttpsError('Not implemented');
}



module.exports = new Https();
module.exports.Https = Https;

