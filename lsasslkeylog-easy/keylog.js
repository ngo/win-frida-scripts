/* ----- COMMON (TLS 1.2 and 1.3) ----- */
var keylog = function(s){
    console.log(s);
    var f = new File("C:\\keylog.log", "a+");
    f.write(s+"\n");
    f.close();
}
var buf2hex = function (buffer) {
	return Array.prototype.map.call(new Uint8Array(buffer), function(x){ return ('00' + x.toString(16)).slice(-2)} ).join('');
}

var client_randoms = {};

/* This is called for TLS1.3 and  for TLS1.2 when RFC 7627 session hashing is used.
 * The first call is with client hello, denoted by msg_type == 1 and version == 0x0303
 * Note that version is 0x0303 both for TLS1.2 and TLS1.3, 
 * which is a backward compatibility hack in TLS 1.3
 */
var shh = Module.findExportByName('ncrypt.dll', 'SslHashHandshake');
if(shh != null){
	Interceptor.attach(shh, {
	    onEnter: function (args) {
			// https://docs.microsoft.com/en-us/windows/win32/seccng/sslhashhandshake
			var buf = ptr(args[2]);
			var len = args[3].toInt32();
			var mem = buf.readByteArray(len);
			var msg_type = buf.readU8();
			var version = buf.add(4).readU16();
			if (msg_type == 1 && version == 0x0303){
				// If we have client random, save it tied to current thread
				var crandom = buf2hex(buf.add(6).readByteArray(32));
				console.log("Got client random from SslHashHandshake: " + crandom);
				client_randoms[this.threadId] = crandom;
			}		
		},
		onLeave: function (retval) {
	    }
	});
}else{
	console.log("SslHashHandshake export not found! Either using a very old windows machine or something is wrong with frida or ncrypt.dll.");
}
/* ----- TLS1.2-specific ----- */

var parse_parameter_list = function(pParameterList, calling_func){
	/*
        typedef struct _NCryptBufferDesc {
            ULONG         ulVersion;
            ULONG         cBuffers;
            PNCryptBuffer pBuffers;
        } NCryptBufferDesc, *PNCryptBufferDesc;

        typedef struct _NCryptBuffer {
            ULONG cbBuffer;
            ULONG BufferType;
            PVOID pvBuffer;
        } NCryptBuffer, *PNCryptBuffer;
     */
    var buffer_count = pParameterList.add(4).readU32();
    var buffers = pParameterList.add(8).readPointer();
    for(var i = 0 ; i < buffer_count ; i ++){
        var buf = buffers.add(16*i);
        var buf_size = buf.readU32();
        var buf_type = buf.add(4).readU32();
        var buf_buf = buf.add(8).readPointer().readByteArray(buf_size);
        // For buf_type values see NCRYPTBUFFER_SSL_* constans in ncrypt.h
        if (buf_type == 20){ // NCRYPTBUFFER_SSL_CLIENT_RANDOM
			console.log("Got client random from " + calling_func+ "'s pParameterList: " + buf2hex(buf_buf));
            return buf2hex(buf_buf);
        }
		//console.log("buf_type " + buf_type);
    }
	
	return null;
}

var parse_h_master_key = function(pMasterKey){
	var NcryptSslKey_ptr = pMasterKey // NcryptSslKey
    var ssl5_ptr = NcryptSslKey_ptr.add(0x10).readPointer();
    var master_key = ssl5_ptr.add(28).readByteArray(48);
	return buf2hex(master_key);
}


/* This one gets called for normal (non-resumed) TLS1.2 sessions. 
 * the phMasterKey will contain the generated key on return
 * pParameterList contains client & server random or a session hash if  RFC 7627 session hashing is used
 * if pParameterList does not contain client random, the one got from SslHashHandshake will be used
 */
Interceptor.attach(Module.getExportByName('ncrypt.dll', 'SslGenerateMasterKey'), {
    onEnter: function (args) {
        // https://docs.microsoft.com/en-us/windows/win32/seccng/sslgeneratemasterkey
        this.phMasterKey = ptr(args[3]);
        this.hSslProvider = ptr(args[0]);
        this.pParameterList = ptr(args[6]);
		this.client_random = parse_parameter_list(this.pParameterList, 'SslGenerateMasterKey') || client_randoms[this.threadId] || "???";
    },
    onLeave: function (retval) {
		var master_key = parse_h_master_key(this.phMasterKey.readPointer());
		console.log("got key from SslGenerateMasterKey");
        keylog("CLIENT_RANDOM " + this.client_random + " " + master_key);
    }
});
/* This one gets called for normal (non-resumed) TLS1.2  sessions on the server for RSA handshakes
 * the phMasterKey will contain the generated key on return
 * pParameterList contains client & server random or a session hash if  RFC 7627 session hashing is used
 * if pParameterList does not contain client random, the one got from SslHashHandshake will be used
 */
Interceptor.attach(Module.getExportByName('ncrypt.dll', 'SslImportMasterKey'), {
    onEnter: function (args) {
		// https://docs.microsoft.com/en-us/windows/win32/seccng/sslimportmasterkey
		this.phMasterKey = ptr(args[2]);
        this.pParameterList = ptr(args[5]);
		// Get client random from the pParameterList, and if that fails - from the value saved by SslHashHandshake handler
		this.client_random = parse_parameter_list(this.pParameterList, 'SslImportMasterKey') || client_randoms[this.threadId] || "???";
	},
	onLeave: function (retval) {
		var master_key = parse_h_master_key(this.phMasterKey.readPointer());
		console.log("got key from SslImportMasterKey");
        keylog("CLIENT_RANDOM " + this.client_random + " " + master_key)
    }
});
/* This one gets called for both resumed and normal sessions.
 * the pMasterKey contains master key
 * pParameterList contains client & server random even if RFC 7627 is in use
 */
Interceptor.attach(Module.getExportByName('ncrypt.dll', 'SslGenerateSessionKeys'), {
    onEnter: function (args) {
        // https://docs.microsoft.com/en-us/windows/win32/seccng/sslgeneratesessionkeys
        this.hMasterKey = ptr(args[1]);
        this.hSslProvider = ptr(args[0]);
        this.pParameterList = ptr(args[4]);
		this.client_random = parse_parameter_list(this.pParameterList, 'SslGenerateSessionKeys') || client_randoms[this.threadId] || "???";
		var master_key = parse_h_master_key(this.hMasterKey);
		console.log("got key from SslGenerateSessionKeys");
        keylog("CLIENT_RANDOM " + this.client_random + " " + master_key);
    },
    onLeave: function (retval) {
    }
});

/* ----- TLS1.3-specific ----- */

var stages = {};

var get_secret_from_BDDD = function(struct_BDDD){
	var struct_3lss = struct_BDDD.add(0x10).readPointer();
	var struct_RUUU = struct_3lss.add(0x20).readPointer();
	var struct_YKSM = struct_RUUU.add(0x10).readPointer();
	var secret_ptr = struct_YKSM.add(0x18).readPointer();
        var size = struct_YKSM.add(0x10).readU32();
	return secret_ptr.readByteArray(size);
}

var setk = Module.findExportByName('ncrypt.dll', 'SslExpandTrafficKeys');
if (setk != null){
	Interceptor.attach(setk, {
	    onEnter: function (args) {
			this.retkey1 = ptr(args[3]);
			this.retkey2 = ptr(args[4]);
			this.client_random = client_randoms[this.threadId] || "???";
			if(stages[this.threadId]){ // We are at the second call
				stages[this.threadId] = null;			
				this.suffix = "TRAFFIC_SECRET_0";
			}else{ // We are at the first call
				stages[this.threadId] = "handshake";
				this.suffix = "HANDSHAKE_TRAFFIC_SECRET";
			}
		},
		onLeave: function (retval) {
			var key1 = get_secret_from_BDDD(this.retkey1.readPointer());
			var key2 = get_secret_from_BDDD(this.retkey2.readPointer());
			keylog("CLIENT_" + this.suffix + " " + this.client_random + " " + buf2hex(key1));
			keylog("SERVER_" + this.suffix + " " + this.client_random + " " + buf2hex(key2));
	    }
	});
}else{
	console.log("SslExpandTrafficKeys export not found! Probably using an old OS such as Win 7. Otherwise report an issue.");
}
var seemk = Module.findExportByName('ncrypt.dll', 'SslExpandExporterMasterKey');
if(seemk != null){
	Interceptor.attach(seemk, {
	    onEnter: function (args) {
			this.retkey = ptr(args[3]);
			this.client_random = client_randoms[this.threadId] || "???";
		},
		onLeave: function (retval) {
			var key = this.retkey.readPointer().add(0x10).readPointer().add(0x20).readPointer().add(0x10).readPointer().add(0x18).readPointer().readByteArray(48);
			keylog("EXPORTER_SECRET " + this.client_random + " " + buf2hex(key));
	    }
	});
}else{
	console.log("SslExpandExporterMasterKey export not found! Probably using an old OS such as Win 7. Otherwise report an issue.");
}
