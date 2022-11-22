'use strict';

/**
  * Message attributes
                                             Binding  Shared  Shared  Shared
                        Binding  Binding  Error    Secret  Secret  Secret
    Att.                Req.     Resp.    Resp.    Req.    Resp.   Error
                                                                    Resp.
    _____________________________________________________________________
    MAPPED-ADDRESS      N/A      M        N/A      N/A     N/A     N/A
    RESPONSE-ADDRESS    O        N/A      N/A      N/A     N/A     N/A
    CHANGE-REQUEST      O        N/A      N/A      N/A     N/A     N/A
    SOURCE-ADDRESS      N/A      M        N/A      N/A     N/A     N/A
    CHANGED-ADDRESS     N/A      M        N/A      N/A     N/A     N/A
    USERNAME            O        N/A      N/A      N/A     M       N/A
    PASSWORD            N/A      N/A      N/A      N/A     M       N/A
    MESSAGE-INTEGRITY   O        O        N/A      N/A     N/A     N/A
    ERROR-CODE          N/A      N/A      M        N/A     N/A     M
    UNKNOWN-ATTRIBUTES  N/A      N/A      C        N/A     N/A     C
    REFLECTED-FROM      N/A      C        N/A      N/A     N/A     N/A
 */

/**
  * 400 (Bad Request): The request was malformed.  The client should not
            retry the request without modification from the previous
            attempt.

    401 (Unauthorized): The Binding Request did not contain a MESSAGE-
            INTEGRITY attribute.

    420 (Unknown Attribute): The server did not understand a mandatory
            attribute in the request.

    430 (Stale Credentials): The Binding Request did contain a MESSAGE-
            INTEGRITY attribute, but it used a shared secret that has
            expired.  The client should obtain a new shared secret and try
            again.

    431 (Integrity Check Failure): The Binding Request contained a
            MESSAGE-INTEGRITY attribute, but the HMAC failed verification.
            This could be a sign of a potential attack, or client
            implementation error.

    432 (Missing Username): The Binding Request contained a MESSAGE-
            INTEGRITY attribute, but not a USERNAME attribute.  Both must be
            present for integrity checks.

    433 (Use TLS): The Shared Secret request has to be sent over TLS, but
            was not received over TLS.

    500 (Server Error): The server has suffered a temporary error. The
            client should try again.

    600 (Global Failure:) The server is refusing to fulfill the request.
            The client should not retry.
 */

const dgram = require("node:dgram");
const tls = require('tls');
const fs = require('node:fs');
var path = require('path');

console.log();

const {generateAuth, HMAC_SHA1, checkTokenFresh} = require("../utils/utils.js");
const Message = require("./message.js");
const { msgTypesInv, INTEGRITY_REQUIRED, MESSAGE_INTEGRITY_PK, errorCodes, CHECKSUM_LENGTH, IPFAMILY } = require("../utils/constants.js");


const tlsOptions = {
    key: fs.readFileSync(path.dirname(path.basename(__dirname)) + '/cert/server/server.key', {encoding: 'utf-8'}),
    cert: fs.readFileSync(path.dirname(path.basename(__dirname)) + '/cert/server/server.crt', {encoding: 'utf-8'}),
    requestCert: false,
};


class Server{
    constructor(config){
        this._addr1 = config.primary.addr;
        this._addr2 = config.secondary.addr;

        this._port1 = config.primary.port;
        this._port2 = config.secondary.port;

        this._tlsSocket = null;
        this._tlsAddress = config.tls.addr;
        this._tlsPort = config.tls.port;

        this._sockets = [];
    }

    _onMessage(msg, rinfo, addr_id, port_id){
        var msgObj = new Message();

        var err = null;

        var socket = this._sockets[2 * addr_id + port_id];

        try{
            try{
                msgObj.deserialize(msg);
            }
            catch(ex){
                // malformed request payload
                err = 400;
            }

            // check checksum integrity (HMAC SHA1)
            if(INTEGRITY_REQUIRED){
                var checkSum = msgObj.getAttr('MESSAGE-INTEGRITY');
                var username = msgObj.getAttr('USERNAME');

                if(checkSum != undefined){
                    if(username != undefined){
                        if(msgObj._unknown_attrs.length == 0){
                            // check is auths are still fresh
                            if(checkTokenFresh(msgObj._transactionId)){
                                var checkSumSlice = msg.slice(0, msg.length - 4 - CHECKSUM_LENGTH);

                                // add padding
                                var paddingLength = (64 - (checkSumSlice.length % 64)) % 64;
                                var paddingBuffer = Buffer.alloc(paddingLength);
                                paddingBuffer.fill(0);

                                checkSumSlice = Buffer.concat([checkSumSlice, paddingBuffer]);
                                var computedCheckSum = HMAC_SHA1(checkSumSlice, MESSAGE_INTEGRITY_PK);

                                if(Buffer.compare(checkSum, computedCheckSum) != 0){
                                    // integrity check failure
                                    err = 431;
                                }
                            }
                            else{
                                // stale credentials
                                err = 430;
                            }
                        }
                        else{
                            // unknown attributes
                            err = 420;
                        }
                    }
                    else{
                        //missing username
                        err = 432;
                    }
                }
                else{
                    // no message integrity attribute present
                    err = 401;
                }
            }

            // change address and port if change requested
            var changeInet = msgObj.getAttr('CHANGE-REQUEST');
            if(changeInet != undefined){
                const {changeIP, changePort} = changeInet;

                if(changeIP) addr_id = 1 - addr_id;
                if(changePort) port_id = 1 - port_id;
            }

            /**
             * if incoming request contains a RESPONSE-ADDRESS attribute
             * server must a return a REFLECTED-FROM attribute to show which the ip the request came from
             * to avoid the STUN server being used as a reflector in DOS attacks
             */
            var responseAddress = msgObj.getAttr('RESPONSE-ADDRESS');

            msgObj.reset();

            if(responseAddress != undefined){
                // add REFLECTED-FROM attribute
                msgObj.addAttr('REFLECTED-FROM', {
                    FAMILY: IPFAMILY,
                    PORT: rinfo.port,
                    IPv4: rinfo.address
                })
            }

            // add mapped address
            msgObj.addAttr('MAPPED-ADDRESS', {
                FAMILY: IPFAMILY,
                PORT: rinfo.port,
                IPv4: rinfo.address
            })


            // add sourced address
            if(socket){
                msgObj.addAttr('SOURCE-ADDRESS', {
                    FAMILY: IPFAMILY,
                    PORT: socket.address().port,
                    IPv4: socket.address().address
                })
            }
            else{
                err = 500;
            }

            var changedSocket = this._sockets[2 * (1 - addr_id) + (1 - port_id)];

            // add changed address
            if(changedSocket){
                msgObj.addAttr('CHANGED-ADDRESS', {
                    FAMILY: IPFAMILY,
                    PORT: changedSocket.address().port,
                    IPv4: changedSocket.address().address
                })
            }
            else{
                err = 500;
            }

            if(err != null){
                throw new Error(`protocol error: ${err}`)
            }

            msgObj.setType(msgTypesInv['Binding Response']);

            if(INTEGRITY_REQUIRED){
                msgObj.addAttr('MESSAGE-INTEGRITY', '');
            }
        }
        catch(ex){
            console.log(ex)
            // reset message and add error code
            msgObj.reset()

            msgObj.setType(msgTypesInv['Binding Error Response']);

            msgObj.addAttr('ERROR-CODE', {
                statusCode: err,
                message: errorCodes[err]
            });
            if(msgObj._unknown_attrs.length > 0){
                msgObj.addAttr('UNKNOWN-ATTRIBUTES', data['unknown_attrs']);
            }
        }
        finally{
            var buf = msgObj.serialize();
            socket.send(buf, 0, buf.length, rinfo.port, rinfo.address);
        }
    }

    _onListening(addr_id, port_id){
        var addr = (addr_id == 0 ? this._addr1 : this._addr2);
        var port = (port_id == 0 ? this._port1 : this._port2);
        console.log("udp server listening on: ", addr, " at port: ", port);
    }

    _onSharedSecretReq(buf){
        /**
         * create username and password for new user and send in shared secret response
         * message integrity not required since TCP stack itself ensures that
         */
        const message = new Message();
        const data = message.deserialize(buf);

        if(data['unknown_attrs'].length > 0){
            // unknown attributes in shared secret request
            message.reset();
            message.setType(msgTypesInv['Shared Secret Error Response'])
            message.addAttr('ERROR-CODE', {
                statusCode: errorCodes[420],
                message: 'unknown attribute in shared secret request'
            });
            message.addAttr('UNKNOWN-ATTRIBUTES', data['unknown_attrs']);
        }
        else{
            const auth = generateAuth(data.transactionId, this._tlsSocket.remoteAddress);
            message.reset();
            message.setType(msgTypesInv['Shared Secret Response']);
            message.addAttr('USERNAME', auth.username);
            message.addAttr('PASSWORD', auth.password);
        }

        var sendBuf = message.serialize();
        this._tlsSocket.write(sendBuf);
    }

    _onSecureConn(socket){
        console.log('secure connection achieved');

        this._tlsSocket = socket;

        this._tlsSocket.on('data', this._onSharedSecretReq.bind(this));
    }

    listen(){
        // UDP - for binding requests
        // create four sockets with 4 address-port combinations
        for(var addr_id = 0; addr_id < 2; addr_id++){
            for(var port_id = 0; port_id < 2; port_id++){
                var socket = dgram.createSocket('udp4');

                if(addr_id == 0){
                    if(port_id == 0){
                        socket.on('message', (msg, rinfo) => {
                            this._onMessage(msg, rinfo, 0, 0);
                        });
                        socket.on('listening', () => {
                            this._onListening(0, 0);
                        });
                    }
                    else{
                        socket.on('message', (msg, rinfo) => {
                            this._onMessage(msg, rinfo, 0, 1);
                        });
                        socket.on('listening', () => {
                            this._onListening(0, 1);
                        });
                    }
                }
                else{
                    if(port_id == 0){
                        socket.on('message', (msg, rinfo) => {
                            this._onMessage(msg, rinfo, 1, 0);
                        });
                        socket.on('listening', () => {
                            this._onListening(1, 0);
                        });
                    }
                    else{
                        socket.on('message', (msg, rinfo) => {
                            this._onMessage(msg, rinfo, 1, 1);
                        });
                        socket.on('listening', () => {
                            this._onListening(1, 1);
                        });
                    }
                }

                var addr = (addr_id == 0 ? this._addr1 : this._addr2);
                var port = (port_id == 0 ? this._port1 : this._port2);

                socket.bind(port, addr);
                this._sockets.push(socket);
            }
        }

        // TLS over TCP - for shared secret request
        const tlsServer = tls.createServer(tlsOptions)

        tlsServer.on('secureConnection', this._onSecureConn.bind(this))

        tlsServer.listen(this._tlsPort, this._tlsAddress, () => {
            console.log("tls server bound on port: ", this._tlsPort)
        })
    }
}

module.exports = Server;
