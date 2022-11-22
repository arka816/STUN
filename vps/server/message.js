"use strict";

/**
 * specs - rfc 3489
 * Author: Arka
 */

const assert = require('assert');

const {
    IPFAMILY,
    HEADER_LENGTH, 
    MAGIC_COOKIE, 
    TRANSACTION_ID_LENGTH, 
    CHECKSUM_LENGTH,
    attrTypes,
    attrTypesInv,
    msgTypes,
    msgTypesInv,
    MESSAGE_INTEGRITY_PK
} = require("../utils/constants.js")

const {HMAC_SHA1, AToInetN} = require("../utils/utils.js");



class Message{
    constructor(){
        this._msgType = null;
        this._transactionId = null;
        this._attrs = [];
    }

    reset(){
        // do not change the transaction id
        this._msgType = null;
        this._attrs = [];
    }

    getAttr(attrType){
        var res = this._attrs.find((_attr) => { return _attr.type == attrType})
        if(res == undefined) return res;
        return res.value;
    }

    addAttr(attrType, attrVal){
        this._attrs.push({type: attrType, value: attrVal});
    }

    setType(msgType){
        this._msgType = msgType;
    }

    setTransactionID(transactionId){
        this._transactionId = transactionId;
    }

    #inetNToA(inet){
        /**
         * @param {Integer} inet IPv4 address as 32 bit integer
         * @return {String} IPv4 address as dot separated string
         */
        var d = inet % 256;

        for(var i = 1; i <= 3; i++){
            inet = Math.floor(inet/256);
            d = (inet % 256) + "." + d;
        }

        return d;
    }

    #readInetAddress(buf, pos){
        /**
         * @param {Buffer} buf message buffer object slice corresponding to attribute value for IP-like objects
         * @param {Integer} pos buffer read offset
         * @return {Object} JSON object with IP family, port and IPv4 address as keys
         */
        // skip the first byte
        pos += 1

        // check if family is IPv4 i.e. 0x01
        var family = buf.readUInt8(pos);
        pos += 1;

        assert(family == 0x01, "ip address family malformed");

        var port = buf.readUInt16BE(pos);
        pos += 2;

        var address = buf.readUInt32BE(pos);
        pos += 4;

        return {
            FAMILY: family,
            PORT: port,
            IPv4: this.#inetNToA(address)
        };
    }

    #writeInetAddress(buf, pos, inet_addr){
        // empty first byte
        buf.writeUInt8(0x00, pos);
        pos += 1;

        // check if ip belongs to the ipv4 family
        var ip = inet_addr['IPv4'];
        assert(ip.split('.').length == 4, "malformed IPv4");

        // write ip family: ipv4
        buf.writeUInt8(inet_addr['FAMILY'], pos);
        pos += 1;

        // write port
        buf.writeUInt16BE(inet_addr['PORT'], pos);
        pos += 2;

        buf.writeUInt32BE(AToInetN(ip), pos);
        pos += 4;

        return pos;
    }

    #readChangeRequest(buf, pos){
        /**
         * @param {Buffer} buf message buffer object slice corresponding to attribute value for IP-like objects
         * @param {Integer} pos buffer read offset
         * @return {Object} JSON object with data about which one(/s) to be changed among address and port
         */
        var data = buf.readUInt32BE(pos);
        pos += 4;

        var changeIP = Boolean(data & (1 << 2));
        var changePort = Boolean(data & (1 << 1));
         
        return {
            changeIP,
            changePort
        }
    }

    #writeChangeRequest(buf, pos, req){
        var i = (req['changeIP'] ? (1 << 2) : 0) + (req['changePort'] ? (1 << 1) : 0);
        buf.writeUInt32BE(i, pos);
        return pos + 4;
    }

    #readError(buf, pos, length){
        var data = buf.readUInt32BE(pos);
        pos += 4;

        // check if first two bytes is zero padding
        var padding = data >> 11;
        assert(padding == 0, 'malformed error padding');

        var statusClass = (data & ((1 << 11) - (1 << 8))) / (1 << 8);
        var statusNumber = data & ((1 << 8) - 1);
        var statusCode = statusClass * 100 + statusNumber;

        var message = buf.toString('utf-8', pos, pos + length - 4);
        pos += length - 4;

        return {
            statusCode,
            message
        }
    }

    #writeError(buf, pos, err){
        var {statusCode, message} = err;
        var statusClass = Math.floor(statusCode / 100);
        var statusNumber = statusCode % 100;
        var status = (statusClass << 8) + statusNumber;
        buf.writeUInt32BE(status, pos);
        pos += 4;

        var msgPaddingLength = (4 - (message.length % 4)) % 4;
        message += ' '.repeat(msgPaddingLength);

        buf.write(message, pos);
        pos += message.length;

        return pos;
    }

    #readUnknownAttrs(buf, pos, length){
        var attrs = [];
        while(length != 0){
            attrs.push(buf.readUInt16BE(pos));
            pos += 2;
            length -= 2;
        }
        return Set(attrs);
    }

    #writeUnknownAttrs(buf, pos, attrs){
        if((attrs.length % 2) != 0){
            attrs.push(attrs[0]);
        }
        for(var attr of attrs){
            assert(typeof(attr) == 'number', 'unknown attribute type list malformed')
            buf.writeUInt16BE(attr, pos);
            pos += 2;
        }
        return pos;
    }

    #writeSHA(buf, pos, message){
        // pad message so that message is length is a multiple of 64 bytes
        var paddingLength = (64 - (message.length % 64)) % 64;
        var paddingBuffer = Buffer.alloc(paddingLength);
        paddingBuffer.fill(0);

        message = Buffer.concat([message, paddingBuffer]);
        var digest = HMAC_SHA1(message, MESSAGE_INTEGRITY_PK);

        digest.copy(buf, pos, 0, digest.length);
        pos += CHECKSUM_LENGTH;

        return pos;
    }

    #getBufferLength(){
        var len = 0;

        // message header
        len += 2 + 2 + TRANSACTION_ID_LENGTH;

        // payload
        for(var attr of this._attrs){
            var attrType = attr['type'];
            var attrVal = attr['value'];

            // for type-length
            len += 4;

            switch(attrType){
                case 'MAPPED-ADDRESS': 
                case 'RESPONSE-ADDRESS':
                case 'SOURCE-ADDRESS':
                case 'REFLECTED-FROM':
                case 'CHANGED-ADDRESS':
                    len += 8;
                    break;
                case 'CHANGE-REQUEST':
                    len += 4;
                    break;
                case 'USERNAME':
                case 'PASSWORD':
                    len += attrVal.length;
                    break;
                case 'ERROR-CODE':
                    var {_, message} = attrVal;
                    var msgPaddingLength = (4 - (message.length % 4)) % 4;
                    len += 4 + message.length + msgPaddingLength;
                    break;
                case 'UNKNOWN-ATTRIBUTES':
                    len += 2 * attrVal.length;
                    break;
                case 'MESSAGE-INTEGRITY':
                    len += CHECKSUM_LENGTH;
                    break;
            }
        }

        return len;
    }

    serialize(){
        // allocate buffer
        var size = this.#getBufferLength();

        var buf = new Buffer.alloc(size);

        var pos = 0;

        // message type
        var msgType = this._msgType;
        assert(
            Object.keys(msgTypes).some((key) => {
                return key == msgType.toString(10);
            }), 
            'invalid message type'
        );
        buf.writeUInt16BE(msgType, pos);
        pos += 2;

        // skip message length; add it later
        var messageLength = size - (4 + TRANSACTION_ID_LENGTH);
        buf.writeUInt16BE(messageLength, pos);
        pos += 2;

        // transaction id
        var tid = this._transactionId;
        assert((tid != undefined) && (tid.length == TRANSACTION_ID_LENGTH), 'malformed transaction id');
        for(var i = 0; i < TRANSACTION_ID_LENGTH; i++){
            buf[pos + i] = tid[i]; 
        }
        pos += TRANSACTION_ID_LENGTH;

        // add T-L-V's for each attribute
        for(var attr of this._attrs){
            var attrType = attr['type'];
            var attrVal = attr['value'];

            // write attrType
            buf.writeUInt16BE(attrTypesInv[attrType], pos);
            pos +=2;

            // skip attribute length; add it later
            buf.writeUInt16BE(0x0000, pos);

            switch(attrType){
                case 'MAPPED-ADDRESS': 
                case 'RESPONSE-ADDRESS':
                case 'SOURCE-ADDRESS':
                case 'REFLECTED-FROM':
                case 'CHANGED-ADDRESS':
                    var endPos = this.#writeInetAddress(buf, pos + 2, attrVal);
                    break;
                case 'CHANGE-REQUEST':
                    var endPos = this.#writeChangeRequest(buf, pos + 2, attrVal);
                    break;
                case 'USERNAME':
                case 'PASSWORD':
                    assert(Buffer.isBuffer(attrVal) && ((attrVal.length % 4) == 0), 'malformed auth parameter');
                    // pos += 2;
                    // buf.write(attrVal, pos);
                    attrVal.copy(buf, pos + 2, 0, attrLength);
                    endPos = pos + 2 + attrVal.length;
                    break;
                case 'ERROR-CODE':
                    var endPos = this.#writeError(buf, pos + 2, attrVal);
                    break;
                case 'UNKNOWN-ATTRIBUTES':
                    var endPos = this.#writeUnknownAttrs(buf, pos + 2, this._unknown_attrs);
                    break;
                case 'MESSAGE-INTEGRITY':
                    var endPos = this.#writeSHA(buf, pos + 2, buf.slice(0, pos - 2));
                    break;
            }

            var attrLength = endPos - (pos + 2);
            
            assert(attrLength <= (1 << 16), 'attribute length limit exceeded');
            buf.writeUInt16BE(attrLength, pos);
            pos = endPos;
        }

        return buf;
    }

    deserialize(buf){
        /**
         * @param {Buffer} buf data to be deserialized
         * @throws {Error} STUN message must be longer than 20 bytes
         * @throws {Error} Message length mismatch
         * deserialize message buffer object
         * splits into headers and message payload
         * parses header into
         *      - message type
         *      - message length
         *      - transaction id
         * parses payload into
         *      - attributes with attribute name and value
         */
        
        // buffer must be longer than 20 bytes
        if(buf.length < HEADER_LENGTH){
            throw new Error("STUN message must be longer than 20 bytes");
        }

        var pos = 0

        var msgType = buf.readUInt16BE(pos);
        pos += 2;
        assert(
            Object.keys(msgTypes).some((key) => {
                return key == msgType.toString(10);
            }), 
            'invalid message type'
        );

        var msgLength = buf.readUInt16BE(pos);
        pos += 2;

        // magicCookie = buf.slice(pos, pos + 4);
        // pos += 4;

        var transactionId = buf.slice(pos, pos + TRANSACTION_ID_LENGTH);
        pos += 16;

        // magic cookie must equal 0x2112A442
        // assert(magicCookie.toString("hex") == MAGIC_COOKIE.toString('hex'));

        // the remaining buffer (payload) must match message length
        if(buf.length - HEADER_LENGTH != msgLength){
            throw new Error("message length in header mismatch");
        }

        var attrs = [], unknown_attrs = [];

        while(pos < buf.length){
            if(buf.length - pos < 4){
                throw new Error('malformed payload');
            }

            var attrType = buf.readUInt16BE(pos);
            // assert(
            //     Object.keys(attrTypes).some((key) => {
            //         return key == attrType.toString(10);
            //     }), 
            //     'invalid attribute type'
            // )

            attrType = attrTypes[attrType];
            pos += 2;

            var attrLength = buf.readUInt16BE(pos);
            pos += 2;


            var attrVal;

            switch(attrType){
                case 'MAPPED-ADDRESS': 
                case 'RESPONSE-ADDRESS':
                case 'SOURCE-ADDRESS':
                case 'REFLECTED-FROM':
                case 'CHANGED-ADDRESS':
                    if(attrLength != 8){
                        throw new Error('Inet address attribute malformed');
                    }
                    attrVal = this.#readInetAddress(buf, pos);
                    break;
                case 'CHANGE-REQUEST':
                    if(attrLength != 4){
                        throw new Error('change request attribute malformed');
                    }
                    attrVal = this.#readChangeRequest(buf, pos);
                    break;
                case 'USERNAME':
                case 'PASSWORD':
                    if(attrLength % 4 != 0){
                        throw new Error(`value of ${attrType} malformed`);
                    }
                    attrVal = buf.slice(pos, pos + attrLength);
                    break;
                case 'ERROR-CODE':
                    if(attrLength % 4 != 0){
                        throw new Error(`value of ${attrType} malformed`);
                    }
                    attrVal = this.#readError(buf, pos, attrLength);
                    break;
                case 'MESSAGE-INTEGRITY':
                    assert(attrLength == CHECKSUM_LENGTH, 'HMAC-SHA1 value must be 20 bytes');
                    attrVal = buf.slice(pos, pos + attrLength);
                    break;
            }

            pos += attrLength;

            if(Object.keys(attrTypesInv).some((key) => {
                return key == attrType;
            })){
                attrs.push({type: attrType, value: attrVal});
            }
            else{
                if(attrTypesInv[attrType] <= 0x7fff){
                    unknown_attrs.push(attrType);
                }
            }
        }

        this._msgType = msgType;
        this._transactionId = transactionId;
        this._attrs = attrs;
        this._unknown_attrs = unknown_attrs;

        return {
            msgType,
            transactionId,
            attrs,
            unknown_attrs
        };
    }
}

module.exports = Message
