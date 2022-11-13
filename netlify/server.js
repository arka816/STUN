const dgram = require("node:dgram");

const socket = dgram.createSocket('udp4');

socket.on('error', (err) => {
    console.log(`server error:\n${err.stack}`);
    server.close();
});

socket.on('message', (msg, rinfo) => {
    console.log(`server got: ${msg} from ${rinfo.address}:${rinfo.port}`);
});

socket.on('listening', () => {
    const address = socket.address();
    console.log(`server listening ${address.address}:${address.port}`);
});

PORT = 3478;
socket.bind(process.env.PORT || PORT);

class Server{
    constructor(a1, a2, p1, p2){
        this._addr1 = a1;
        this._addr2 = a2;

        this._port1 = p1;
        this._port2 = p2;

        this._sockets = [];
    }

    _onMessage(msg, rinfo, addr_id, port_id){
        var msgObj = Message();

        try{
            msgObj.deserialize(msg);
        }
        catch(e){
            console.log("error in deserialization", e);
        }

        var changeInet = msgObj.getAttribute('CHANGE-REQUEST');
        if(changeInet != undefined){
            const {changeIP, changePort} = changeInet;

            if(changeIP) addr_id = 1 - addr_id;
            if(changePort) port_id = 1 - port_id;
        }

        msgObj.reset();

        msgObj.addAttr('')
    }

    listen(){
        for(var addr_id = 0; addr_id < 2; addr_id++){
            for(var port_id = 0; port_id < 2; port_id++){
                var socket = dgram.createSocket('udp4');

                socket.on('message', (msg, rinfo) => {
                    this._onMessage(msg, rinfo, addr_id, port_id);
                })

                var addr = (addr_id == 0 ? this._addr1 : this._addr2);
                var port = (port_id == 0 ? this._port1 : this._port2);

                socket.bind(port, addr);
            }
        }
    }
}
