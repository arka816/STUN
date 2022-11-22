'use strict';

const fs = require("fs");
const ini = require("ini");
const lodash = require("lodash");

const Server = require("./server/server.js");

const config = (function initConfig(){
    var config = {};
    var defaults = {
        server: {
            index : 0
        },
        primary: {
            addr: '0.0.0.0',
            port: '3478'
        },
        secondary: {
            addr: '68.178.166.10',
            port: '3479'
        },
        tls: {
            addr: '0.0.0.0',
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
