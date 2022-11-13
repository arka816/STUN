"use strict";

/**
 * specs - rfc 3489
 * Author: Arka
 */

const crypto = require('crypto');


const HEADER_LENGTH = 20
const MAGIC_COOKIE = 0x2112A442; /* RFC - 5389 */
const TRANSACTION_ID_LENGTH = 16;

const attrTypes = {
    0x0001: 'MAPPED-ADDRESS',
    0x0002: 'RESPONSE-ADDRESS',
    0x0003: 'CHANGE-REQUEST',
    0x0004: 'SOURCE-ADDRESS',
    0x0005: 'CHANGED-ADDRESS',
    0x0006: 'USERNAME',
    0x0007: 'PASSWORD',
    0x0008: 'MESSAGE-INTEGRITY',
    0x0009: 'ERROR-CODE',
    0x000a: 'UNKNOWN-ATTRIBUTES',
    0x000b: 'REFLECTED-FROM'
}

const msgTypes = {
    0x0001  :  'Binding Request',
    0x0101  :  'Binding Response',
    0x0111  :  'Binding Error Response',
    0x0002  :  'Shared Secret Request',
    0x0102  :  'Shared Secret Response',
    0x0112  :  'Shared Secret Error Response'
}

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
        return this._attrs.find((_attr) => { return _attr.type == attrType});
    }

    addAttr(attrType, attrVal){
        this._attrs.push({type: attrType, value: attrVal});
    }

    setType(msgType){
        this._msgType = msgType;
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

    #AToInetN(a){
        var inet = 0;

        for(var loc of a.split('.')){
            loc = parseInt(loc);
            assert((loc >= 0) && (loc < 256), 'malformed IPv4');
            inet = inet << 8;
            inet += loc;
        }

        return inet;
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

        buf.writeUInt32BE(this.#AToInetN(ip), pos);
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
        var padding = data && ((1 << 32) - (1 << 11));
        assert(padding == 0, 'malformed error padding');

        var statusClass = data && ((1 << 11) - (1 << 8));
        var statusNumber = data && (1 << 8);
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

        msgPaddingLength = (4 - (message.length % 4)) % 4;
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

        var shaSum = crypto.createHash('sha1');
        shaSum.update(message);
        var digest = shaSum.digest('utf-8');

        buf.write(digest, pos);
        pos += 20;

        return pos;
    }

    serialize(buf, data){
        var pos = 0;

        // message type
        var msgType = data['msgType'];
        assert(Object.keys(msgTypes).includes(msgType), 'invalid message type');
        buf.writeUInt16BE(msgType, pos);
        pos += 2;

        // skip message length; add it later
        var messageLengthStartPos = pos;
        buf.writeUInt16BE(0x0000, pos);
        pos += 2;

        // transaction id
        var tid = data['tid'];
        assert((tid != undefined) && (tid.length == TRANSACTION_ID_LENGTH), 'malformed transaction id');
        for(var i = 0; i < TRANSACTION_ID_LENGTH; i++){
            buf[pos + i] = tid[i]; 
        }
        pos += TRANSACTION_ID_LENGTH;

        var messagePayloadStartPos = pos;

        // add T-L-V's for each attribute
        for(var attr of data['attrs']){
            var attrType = attr['type'];
            var attrVal = attr['value'];

            // write attrType
            buf.writeUInt16BE(attrType, pos);
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
                    assert((typeof(attrVal) == 'string') && ((attrVal.length % 4) == 0), 'malformed auth parameter');
                    pos += 2;
                    buf.write(attrVal, pos);
                    endPos = pos + attrVal.length;
                    break;
                case 'ERROR-CODE':
                    var endPos = this.#writeError(buf, pos + 2, attrVal);
                    break;
                case 'UNKNOWN-ATTRIBUTES':
                    var endPos = this.#writeUnknownAttrs(buf, pos + 2, attrVal);
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

        var messageLength = pos - messagePayloadStartPos;
        buf.writeUInt16BE(messageLength, messageLengthStartPos);
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
         *      - magic cookie
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
        assert(Object.keys(msgTypes).includes(msgType), 'invalid message type');

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

        attrs = [];

        while(pos < buf.length){
            if(buf.length - pos < 4){
                throw new Error('malformed payload');
            }

            var attrType = buf.readUInt16BE(pos);
            attrType = attrTypes[attrType];
            pos += 2;

            attrLength = buf.readUInt16BE(pos);
            pos += 2;

            var attrVal;

            switch(attrType){
                case 'MAPPED-ADDRESS': 
                case 'RESPONSE-ADDRESS':
                case 'SOURCE-ADDRESS':
                case 'REFLECTED-FROM':
                case 'CHANGED-ADDRESS':
                    if(attrLength != 4){
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
                    attrVal = buf.toString('utf-8', pos, pos + attrLength);
                    break;
                case 'ERROR-CODE':
                    if(attrLength % 4 != 0){
                        throw new Error(`value of ${attrType} malformed`);
                    }
                    attrVal = this.#readError(buf, pos, attrLength);
                    break;
                case 'UNKNOWN-ATTRIBUTES':
                    if(attrLength % 4 != 0){
                        throw new Error(`value of ${attrType} malformed`);
                    }
                    attrVal = this.#readUnknownAttrs(buf, pos, attrLength);
                    break;
                case 'MESSAGE-INTEGRITY':
                    assert(attrLength == 20, 'HMAC-SHA1 value must be 20 bytes');
                    attrVal = buf.toString('utf-8', pos, pos + attrLength);
                    break;
            }

            pos += attrLength;

            attrs.push({type: attrType, value: attrVal});
        }

        this._msgType = msgType;
        this._transactionId = transactionId;
        this._attrs = attrs;

        return {
            msgType,
            transactionId,
            attrs
        };
    }
}