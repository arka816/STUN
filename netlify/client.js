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

const port = 8000;
const hostname = '127.0.0.1';

const tls = require('tls');
const fs = require('fs');

const secureContext = tls.createSecureContext({
    ca:fs.readFileSync('cert/ca/ca.crt', {encoding: 'utf-8'})
});

const options = {
    host: hostname,
    port: port,
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
} = require("./constants.js");

const Message = require("./message.js");

const {randTransID} = require("./utils.js");
const { assert } = require('console');


class Client{
    constructor(){
        this._session = null;

        this._sharedSecretReq();

        this._bindingReq();
    }

    _sharedSecretReq(){
        const socket = tls.connect(options, () => {
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
        })
        .on('data', (buf) => {
            socket.end();

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
        })
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

    _bindingReq(){
        
    }
}


// shared secret request
client = new Client();
