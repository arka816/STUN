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
    REF
 */

const tls = require('tls');
const fs = require('fs');
const dgram = require("node:dgram");

const secureContext = tls.createSecureContext({
    ca:fs.readFileSync('../cert/ca/ca.crt', {encoding: 'utf-8'})
});

const tlsOptions = {
    rejectUnauthorized: false,
    requestCert: true,
    secureContext: secureContext
};

const {
    HEADER_LENGTH, 
    MAGIC_COOKIE, 
    TRANSACTION_ID_LENGTH, 
    CHECKSUM_LENGTH,
    attrTypes,
    msgTypes,
    msgTypesInv
} = require("../utils/constants.js");

const Message = require("../server/message.js");

const {randTransID, printBuffer} = require("../utils/utils.js");
const { assert } = require('console');


class Client{
    constructor(){
        this._local_addr = '0.0.0.0';
        this._local_port = 3000;

        this._remote_addr = '68.178.164.189';
        this._remote_port = 3478;

        this._remote_tls_port = 8000;

        this._session = {};
        this._tlsSocket = null;
        this._udpSocket = null;

        this._sharedSecretReq();
    }

    _onSharedSecretResponse(buf){
        this._tlsSocket.end();

        var message = new Message();
        message.deserialize(buf);

        if(message._msgType == msgTypesInv['Shared Secret Response']){
            const username = message.getAttr('USERNAME');
            const password = message.getAttr('PASSWORD');

            assert(username != null && username != undefined && username.length == 36, "malformed username")
            assert(password != null && password != undefined && password.length == 20, "malformed password")

            this._session = {
                ...this._session,
                username: username, 
                password: password
            }
        }
        else if(message._msgType == msgTypesInv['Shared Secret Error Response']){
            console.log(message.getAttr('ERROR-CODE'))
            if(message.getAttr('ERROR-CODE').statusCode == 420){
                throw new Error(message.getAttr('ERROR-CODE').message)
            }
        }
        else{
            throw new Error("message type not recognized");
        }

        // shared secret response received 
        this._createUdpSockets();
    }

    _sharedSecretReq(){
        const socket = tls.connect(
            {
                ...tlsOptions,
                host: this._remote_addr, 
                port: this._remote_tls_port
            }, 
            () => {
                this._tlsSocket = socket;

                process.on('SIGINT',function(){
                    this._tlsSocket.destroy();
                }.bind(this));

                console.log('client connected', socket.authorized ? 'authorized' : 'unauthorized');

                if (!socket.authorized) {
                    console.log("Error: ", socket.authorizationError);
                    socket.end();
                }
                else{
                    // form shared secret request message
                    var message = new Message();
                    var transactionID = randTransID();

                    this._session = {
                        ...this._session,
                        tid: transactionID
                    }
            
                    message.setType(msgTypesInv['Shared Secret Request']);
                    message.setTransactionID(transactionID);
            
                    var buf = message.serialize();
            
                    socket.write(buf);
                    socket.end();
                }
            }
        )
        .on('data', this._onSharedSecretResponse.bind(this))
        .on('close', () => {
            console.log("Shared Secret Connection closed");
        })
        .on('end', () => {
            console.log("Shared Secret connection ended");
        })
        .on('error', (error) => {
            console.error(error);
            socket.destroy();
        });
    }

    _onListening(){

    }

    _onReceived(msg, rinfo){
        this._bres = new Message();

        printBuffer(msg);

        this._bres.deserialize(msg);

        console.log(this._bres._attrs);
    }

    _createUdpSockets(){
        this._udpSocket = dgram.createSocket('udp4');

        this._udpSocket.on("listening", this._onListening.bind(this));
        this._udpSocket.on("message", this._onReceived.bind(this));
        
        this._udpSocket.bind(this._local_port, this._local_addr, this._bindingReq.bind(this))

        process.on('SIGINT',function(){
            this._udpSocket.destroy();
        }.bind(this));
    }

    _bindingReq(){
        this._breq = new Message();

        this._breq.setType(msgTypesInv['Binding Request']);
        this._breq.setTransactionID(this._session.tid);

        this._breq.addAttr('USERNAME', this._session.username);
        this._breq.addAttr('MESSAGE-INTEGRITY', '');

        var buf = this._breq.serialize();

        console.log(buf);

        this._udpSocket.send(buf, 0, buf.length, this._remote_port, this._remote_addr);
    }
}


// shared secret request
var client = new Client();
