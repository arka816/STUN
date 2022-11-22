'use strict';

const crypto = require('crypto');

const IPFAMILY = 0x01;

const HEADER_LENGTH = 20
const MAGIC_COOKIE = 0x2112A442; /* RFC - 5389 */
const TRANSACTION_ID_LENGTH = 16;
const CHECKSUM_LENGTH = 20;

const INTEGRITY_REQUIRED = true;
const TLS_AUTH = true;

const AUTH_TIMEOUT = 10 * 60; /* 10 minutes to invalidate the auth credentials */
const AUTH_BYTE_SIZE = 32;

const AUTH_PREFIX_SIZE = 11;
const AUTH_MINS_MOD = 20;

const AUTH_USERNAME_PK = crypto.randomBytes(16).toString('utf-8');
const AUTH_PASSWORD_PK = crypto.randomBytes(16).toString('utf-8');

const MESSAGE_INTEGRITY_PK = 'mavis';

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

const attrTypesInv = {
    'MAPPED-ADDRESS': 0x0001,
    'RESPONSE-ADDRESS': 0x0002,
    'CHANGE-REQUEST': 0x0003,
    'SOURCE-ADDRESS': 0x0004,
    'CHANGED-ADDRESS': 0x0005,
    'USERNAME': 0x0006,
    'PASSWORD': 0x0007,
    'MESSAGE-INTEGRITY': 0x0008,
    'ERROR-CODE': 0x0009,
    'UNKNOWN-ATTRIBUTES': 0x000a,
    'REFLECTED-FROM': 0x000b
}

const msgTypes = {
    0x0001  :  'Binding Request',
    0x0101  :  'Binding Response',
    0x0111  :  'Binding Error Response',
    0x0002  :  'Shared Secret Request',
    0x0102  :  'Shared Secret Response',
    0x0112  :  'Shared Secret Error Response'
}

const msgTypesInv = {
    'Binding Request': 0x0001,
    'Binding Response': 0x0101,
    'Binding Error Response': 0x0111,
    'Shared Secret Request': 0x0002,
    'Shared Secret Response': 0x0102,
    'Shared Secret Error Response': 0x0112
}

const errorCodes = {
    400: 'malformed request',
    401: 'No MESSAGE-INTEGRITY attribute',
    420: 'Unknown Attribute',
    430: 'Stale Credentials',
    431: 'Integrity Check Failure',
    432: 'Missing Username',
    433: 'Shared Secret Request must be sent over TLS',
    500: 'Server Error',
    600: 'Global Error'
}

module.exports = {
    IPFAMILY,
    HEADER_LENGTH,
    MAGIC_COOKIE,
    TRANSACTION_ID_LENGTH,
    CHECKSUM_LENGTH,
    INTEGRITY_REQUIRED,
    TLS_AUTH,
    AUTH_TIMEOUT,
    AUTH_BYTE_SIZE,
    AUTH_PREFIX_SIZE,
    AUTH_MINS_MOD,
    AUTH_USERNAME_PK,
    AUTH_PASSWORD_PK,
    MESSAGE_INTEGRITY_PK,
    attrTypes,
    attrTypesInv,
    msgTypes,
    msgTypesInv,
    errorCodes
}
