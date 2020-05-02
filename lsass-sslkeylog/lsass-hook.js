var modules = Process.enumerateModules();
var SCHANNEL = null;
var buf2hex = function (buffer) {
  return Array.prototype.map.call(new Uint8Array(buffer), function(x){ return ('00' + x.toString(16)).slice(-2)} ).join('');
}
var keylog = function(s){
    send(s);
    if(__WRITE_KEYLOG__){
        var f = new File(__KEYLOG_FILE__, "a+");
        f.write(s+"\n");
        f.close();
    }
}

var client_randoms = {};

for(var i in modules){
    var module = modules[i];
    if(module.name.startsWith("schannel")){
        send(module.base);
    }
}
var KeyHelper_hook = {
    onEnter: function (args) {
        var this_ = args[0];
        //console.log("THIS: " + this_);
        //console.log(this_.readByteArray(0x300));
        var unixtime_first_bytes = (((Date.now() / 1000) & 0xffff0000)>>16).toString(16)
        var pattern = unixtime_first_bytes.slice(0,2) + ' ' +  unixtime_first_bytes.slice(2,4)
        var results = Memory.scanSync(this_, 0x300, pattern)
        if(results.length > 0){
            client_randoms[this.threadId] = buf2hex(results[0].address.readByteArray(32));
        }
    }
}
recv('breakpoints', function(value) {
    var addrs = value.payload.split('|');
    for(var i in addrs){
        var addr = ptr(addrs[i]);
        console.log("Setting up breakpoint at " + addr)
        Interceptor.attach(addr, KeyHelper_hook);
    }
});

Interceptor.attach(Module.getExportByName('ncrypt.dll', 'SslGenerateMasterKey'), { 
    onEnter: function (args) {
        // https://docs.microsoft.com/en-us/windows/win32/seccng/sslgeneratemasterkey
        this.phMasterKey = ptr(args[3]);
        this.hSslProvider = ptr(args[0]);
    },
    onLeave: function (retval) {
        var ret_addr = this.returnAddress;
        var NcryptSslKey_ptr = this.phMasterKey.readPointer(); // NcryptSslKey
        var ssl5_ptr = NcryptSslKey_ptr.add(0x10).readPointer();
        var master_key = ssl5_ptr.add(28).readByteArray(48);
        var crandom = "???";
        if(client_randoms[this.threadId]) crandom = client_randoms[this.threadId];
        keylog("CLIENT_RANDOM " + crandom + " " + buf2hex(master_key))
    }

});

