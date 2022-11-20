const Server = require("./server.js");

const config = {
    addr1: '127.0.0.1',
    addr2: '127.0.0.2',
    port1: '3478',
    port2: '3479',
    tlsPort: 8000
};

server = new Server(config);
server.listen();