const crypto = require('crypto');
const assert = require('assert');

const {
    AUTH_TIMEOUT, 
    AUTH_BYTE_SIZE, 
    TRANSACTION_ID_LENGTH, 
    AUTH_PREFIX_SIZE, 
    AUTH_MINS_MOD, 
    AUTH_USERNAME_PK, 
    AUTH_PASSWORD_PK
} = require("./constants.js")

var AUTH_LIST = {};


function generateAuth(transactionID, clientIP){
    /**
     * @param {transactionID} Buffer 
     * @param {clientIP} string 
     * @return {Buffer} username - 48 byte
     * @return {Buffer} password - 32 byte
     * generate 32 byte unique username and password
     * to be communicated as a shared secret response
     * over TLS over TCP
     */
    if(transactionID in AUTH_LIST){
        return AUTH_LIST[transactionID];
    }

    const prefix = crypto.randomBytes(AUTH_PREFIX_SIZE);

    const mins = new Buffer.alloc(1);
    mins.writeUInt8(new Date().getMinutes() % AUTH_MINS_MOD);

    const IP = new Buffer.alloc(4);
    IP.writeUInt32BE(AToInetN(clientIP));

    const hmac = HMAC_SHA1(Buffer.concat([prefix, mins, IP]), AUTH_USERNAME_PK);

    const username = Buffer.concat([prefix, mins, IP, hmac]);
    const password = HMAC_SHA1(username, AUTH_PASSWORD_PK);

    console.log(username, password);

    AUTH_LIST[transactionID] = {username, password};

    setTimeout(() => {
        delete AUTH_LIST[transactionID];
    }, AUTH_TIMEOUT);

    return {
        username: username,
        password: password
    }
}

function AToInetN(a){
    var inet = 0;

    for(var loc of a.split('.')){
        loc = parseInt(loc);
        assert((loc >= 0) && (loc < 256), 'malformed IPv4');
        inet = inet << 8;
        inet += loc;
    }

    return inet;
}

function checkTokenFresh(transactionID){
    return transactionID in AUTH_LIST;
}

function HMAC_SHA1(message, key){
    /**
     * @returns {Buffer} 20 byte hmac value for the message using a private key and sha256
     */
    const hash = crypto.createHmac('sha1', key).update(message).digest();
    console.log(hash.length)
    return hash;
}

/**
 * @returns {Buffer} Returns a 16-byte random sequence
 */
function randTransID(){
    var seed = process.pid.toString(16);
    seed += Math.round(Math.random() * 0x100000000).toString(16);
    seed += (new Date()).getTime().toString(16);

    var md5 = crypto.createHash('md5');
    md5.update(seed);
    return md5.digest();
}

module.exports = {
    generateAuth,
    HMAC_SHA1,
    checkTokenFresh,
    randTransID,
    AToInetN
}
