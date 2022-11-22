'use strict';

const fs = require("fs");
const ini = require("ini");
const lodash = require("lodash");

const Server = require("./server/server.js");

const config = (function initConfig(){
    var config = {};
    var defaults = {
        primary: {
            addr: '127.0.0.1',
            port: '3478'
        },
        secondary: {
            addr: '127.0.0.2',
            port: '3479'
        },
        tls: {
            addr: '127.0.0.1',
            port: '8000'
        }
    };

    try{
        config = ini.parse(fs.readFileSync('./stun.ini', 'utf-8'));
    }
    catch(e){
        if (e.code === 'ENOENT') {
            console.warn('Config file not found:', e);
        } else {
            throw e;
        }
    }

    return lodash.defaultsDeep(config, defaults);
})();

var server = new Server(config);
server.listen();
