var HANDLE_TABLE = {}

var buf2hex = function (buffer) {
  return Array.prototype.map.call(new Uint8Array(buffer), function(x){ return ('00' + x.toString(16)).slice(-2)} ).join('');
}
var keylog = function(s){
    console.log(s);
    var f = new File("C:\\keylog.log", "a+");
    f.write(s+"\n");
    f.close();
}

var read_PPORT_MESSAGE = function(msg){
    var ret = {
        raw:"",
        len:"",
        formatted:""
    };
    if(msg != 0x0){
        ret.msglen = ptr(msg).readU16();
        if(ret.msglen > 0){
            ret.len = ptr(msg).add(0x02).readU16();
            var headerlen = ret.len - ret.msglen;
            if(headerlen > 0 && ret.len > 0){
                ret.raw = ptr(msg).readByteArray(ret.len);
                ret.raw_header = ptr(msg).readByteArray(headerlen);
                ret.body_ptr = ptr(msg).add(headerlen);
                ret.raw_body = ptr(msg).add(headerlen).readByteArray(ret.msglen);
                ret.body = {}
                ret.body.req_type = ret.body_ptr.readU32();
                var msg_decoded = "";
                if(ret.body.req_type == 3){ //RPC_RESPONSE_TYPE_SUCCESS
                    ret.body.resp_len = ret.msglen - 6*4
                    ret.body.resp_ptr = ptr(msg).add(headerlen).add(6*4)
                    ret.body.response = ret.body.resp_ptr.readByteArray(ret.body.resp_len)
                    ret.formatted += "RPC_RESPONSE_TYPE_SUCCESS\n" + hexdump(ret.body.response)
                }
            }
        }
    };
    return ret;
};

var cur_client_rnd = {};
Interceptor.attach(Module.getExportByName('ncrypt.dll', 'SslGenerateMasterKey'), { 
    onEnter: function (args) {
        // https://docs.microsoft.com/en-us/windows/win32/seccng/sslgeneratemasterkey
        this.phMasterKey = ptr(args[3]);
        this.hSslProvider = ptr(args[0]);
    },
    onLeave: function (retval) {
        var NcryptSslKey_ptr = this.phMasterKey.readPointer(); // NcryptSslKey
        var ssl5_ptr = NcryptSslKey_ptr.add(0x10).readPointer();
        var master_key = ssl5_ptr.add(28).readByteArray(48);
        console.log(this.threadId);
        if(cur_client_rnd[this.threadId]){
            keylog("CLIENT_RANDOM " + cur_client_rnd[this.threadId] + " " + buf2hex(master_key));
            cur_client_rnd[this.threadId] = null;
        }else{
            keylog("CLIENT_RANDOM ??? " + buf2hex(master_key));
        }
    }

});
Interceptor.attach(Module.getExportByName('ntdll.dll', 'NtAlpcSendWaitReceivePort'), {
    onEnter: function (args) {
        //https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html#a139ba6b1a2410cacb224c91826c19246
        this.SendMessage = args[2];
        this.ReceiveMessage = args[4];
        // when tracing LSASS, ReceiveMessage, surprizingly, contains LSASS->mstsc messages.
        var msg = read_PPORT_MESSAGE(this.ReceiveMessage);
        /* TODO: this is a hack based on what I saw in ALPC exchange
         *  the client secret is always preceeded by 03 03. 
         *  Also, the client secret starts with teh timestamp, so I add two first bytes of current time
         *
         *  Most probably this is different for different versions of windows
         *  additional exploration is needed
         *
         *  
         */
        //if(msg.raw) console.log(hexdump(msg.raw));
        var unixtime_first_bytes = (((Date.now() / 1000) & 0xffff0000)>>16).toString(16)
        if(msg.body && msg.body.resp_ptr){
            var results = Memory.scanSync(
                    msg.body.resp_ptr,
                    msg.body.resp_len,
                    '03 03 ' + unixtime_first_bytes.slice(0,2) + ' ' +  unixtime_first_bytes.slice(2,4)
            );
            if(results.length > 0){
                cur_client_rnd[this.threadId] =  buf2hex(results[0].address.add(2).readByteArray(0x20));
                console.log(this.threadId + ' got client random ' + cur_client_rnd[this.threadId]);
            }
         }
    },
    onLeave: function (retval) {
    }
});
