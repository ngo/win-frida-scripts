/* ----- COMMON (TLS 1.2 and 1.3) ----- */
var keylog = function(s) {
    console.log(s);
    var f = new File("C:\\keylog.log", "a+");
    f.write(s + "\n");
    f.close();
}
var buf2hex = function(buffer) {
    return Array.prototype.map.call(new Uint8Array(buffer), function(x) { return ('00' + x.toString(16)).slice(-2) }).join('');
}

var client_randoms = {};

// Modern API approach: Get the module handle once.
const ncrypt = Process.getModuleByName('ncrypt.dll');
if (ncrypt) {
    console.log("Module 'ncrypt.dll' found. Applying hooks...");

    /* Hook SslHashHandshake */
    const shh = ncrypt.getExportByName('SslHashHandshake');
    if (shh) {
        Interceptor.attach(shh, {
            onEnter: function(args) {
                var buf = ptr(args[2]);
                var msg_type = buf.readU8();
                var version = buf.add(4).readU16();
                if (msg_type == 1 && version == 0x0303) {
                    var crandom = buf2hex(buf.add(6).readByteArray(32));
                    console.log("Got client random from SslHashHandshake: " + crandom);
                    client_randoms[this.threadId] = crandom;
                }
            }
        });
    } else {
        console.log("SslHashHandshake export not found!");
    }

    /* ----- TLS 1.2 Helper Functions ----- */
    var parse_parameter_list = function(pParameterList, calling_func) {
        var buffer_count = pParameterList.add(4).readU32();
        var buffers = pParameterList.add(8).readPointer();
        for (var i = 0; i < buffer_count; i++) {
            var buf = buffers.add(16 * i);
            var buf_size = buf.readU32();
            var buf_type = buf.add(4).readU32();
            if (buf_type == 20) { // NCRYPTBUFFER_SSL_CLIENT_RANDOM
                var buf_buf = buf.add(8).readPointer().readByteArray(buf_size);
                console.log("Got client random from " + calling_func + "'s pParameterList: " + buf2hex(buf_buf));
                return buf2hex(buf_buf);
            }
        }
        return null;
    }

    var parse_h_master_key = function(pMasterKey) {
        var NcryptSslKey_ptr = pMasterKey;
        var ssl5_ptr = NcryptSslKey_ptr.add(0x10).readPointer();
        var master_key = ssl5_ptr.add(28).readByteArray(48);
        return buf2hex(master_key);
    }

    /* Hook SslGenerateMasterKey */
    const sgmk = ncrypt.getExportByName('SslGenerateMasterKey');
    if (sgmk) {
        Interceptor.attach(sgmk, {
            onEnter: function(args) {
                this.phMasterKey = ptr(args[3]);
                var pParameterList = ptr(args[6]);
                this.client_random = parse_parameter_list(pParameterList, 'SslGenerateMasterKey') || client_randoms[this.threadId] || "???";
            },
            onLeave: function(retval) {
                var master_key = parse_h_master_key(this.phMasterKey.readPointer());
                console.log("got key from SslGenerateMasterKey");
                keylog("CLIENT_RANDOM " + this.client_random + " " + master_key);
            }
        });
    }

    /* Hook SslImportMasterKey */
    const simk = ncrypt.getExportByName('SslImportMasterKey');
    if (simk) {
        Interceptor.attach(simk, {
            onEnter: function(args) {
                this.phMasterKey = ptr(args[2]);
                var pParameterList = ptr(args[5]);
                this.client_random = parse_parameter_list(pParameterList, 'SslImportMasterKey') || client_randoms[this.threadId] || "???";
            },
            onLeave: function(retval) {
                var master_key = parse_h_master_key(this.phMasterKey.readPointer());
                console.log("got key from SslImportMasterKey");
                keylog("CLIENT_RANDOM " + this.client_random + " " + master_key);
            }
        });
    }

    /* Hook SslGenerateSessionKeys */
    const sgsk = ncrypt.getExportByName('SslGenerateSessionKeys');
    if (sgsk) {
        Interceptor.attach(sgsk, {
            onEnter: function(args) {
                var hMasterKey = ptr(args[1]);
                var pParameterList = ptr(args[4]);
                this.client_random = parse_parameter_list(pParameterList, 'SslGenerateSessionKeys') || client_randoms[this.threadId] || "???";
                var master_key = parse_h_master_key(hMasterKey);
                console.log("got key from SslGenerateSessionKeys");
                keylog("CLIENT_RANDOM " + this.client_random + " " + master_key);
            }
        });
    }

    /* ----- TLS 1.3 Helper Functions and Hooks ----- */
    var stages = {};
    var get_secret_from_BDDD = function(struct_BDDD) {
        var struct_3lss = struct_BDDD.add(0x10).readPointer();
        var struct_RUUU = struct_3lss.add(0x20).readPointer();
        var struct_YKSM = struct_RUUU.add(0x10).readPointer();
        var secret_ptr = struct_YKSM.add(0x18).readPointer();
        var size = struct_YKSM.add(0x10).readU32();
        return secret_ptr.readByteArray(size);
    }

    /* Hook SslExpandTrafficKeys */
    const setk = ncrypt.getExportByName('SslExpandTrafficKeys');
    if (setk) {
        Interceptor.attach(setk, {
            onEnter: function(args) {
                this.retkey1 = ptr(args[3]);
                this.retkey2 = ptr(args[4]);
                this.client_random = client_randoms[this.threadId] || "???";
                if (stages[this.threadId]) {
                    stages[this.threadId] = null;
                    this.suffix = "TRAFFIC_SECRET_0";
                } else {
                    stages[this.threadId] = "handshake";
                    this.suffix = "HANDSHAKE_TRAFFIC_SECRET";
                }
            },
            onLeave: function(retval) {
                var key1 = get_secret_from_BDDD(this.retkey1.readPointer());
                var key2 = get_secret_from_BDDD(this.retkey2.readPointer());
                keylog("CLIENT_" + this.suffix + " " + this.client_random + " " + buf2hex(key1));
                keylog("SERVER_" + this.suffix + " " + this.client_random + " " + buf2hex(key2));
            }
        });
    } else {
        console.log("SslExpandTrafficKeys export not found!");
    }

    /* Hook SslExpandExporterMasterKey */
    const seemk = ncrypt.getExportByName('SslExpandExporterMasterKey');
    if (seemk) {
        Interceptor.attach(seemk, {
            onEnter: function(args) {
                this.retkey = ptr(args[3]);
                this.client_random = client_randoms[this.threadId] || "???";
            },
            onLeave: function(retval) {
                var key = this.retkey.readPointer().add(0x10).readPointer().add(0x20).readPointer().add(0x10).readPointer().add(0x18).readPointer().readByteArray(48);
                keylog("EXPORTER_SECRET " + this.client_random + " " + buf2hex(key));
            }
        });
    } else {
        console.log("SslExpandExporterMasterKey export not found!");
    }

} else {
    console.log("Module 'ncrypt.dll' not found in the target process. The script will not run.");
}
