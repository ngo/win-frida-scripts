#!/usr/bin/env python3
import argparse
import sys
import subprocess
import os.path

import frida
from pdb_sym_lookup import SymLookup

parser = argparse.ArgumentParser()
parser.add_argument("-H", "--host", help="connect to remote frida-server on HOST")
parser.add_argument("--schannel-dll", help="schannel dll file")
parser.add_argument("--schannel-pdb", help="schannel pdb file (if dll is specified - where to download)")
parser.add_argument("--remote-keylog", help="remote keylog file", default=None)
parser.add_argument("--local-keylog", help="remote keylog file", default=None, type=argparse.FileType('a+'))
args = parser.parse_args()

if not args.schannel_dll and not args.schannel_pdb:
    sys.stderr.write("Either DLL or PDB should be specified\n")
    sys.exit(1)
if args.schannel_dll:
    if args.schannel_pdb:
        if os.path.isfile(args.schannel_pdb):
            sys.stderr.write("Both DLL and PDB specified, ignoring PDB\n")
    subprocess.check_call(["symchk.py", args.schannel_dll])
    args.schannel_pdb = "./schannel.pdb"
        
if args.host:
    session = frida.get_device_manager().add_remote_device(args.host).attach("lsass.exe")
else:
    session = frida.attach("lsass.exe")

src = open("lsass-hook.js").read()
if args.remote_keylog is None:
    src = src.replace('__WRITE_KEYLOG__', "0")
else:
    src = src.replace('__WRITE_KEYLOG__', "1")
    src = src.replace('__KEYLOG_FILE__', repr(args.remote_keylog))

script = session.create_script(src)

breakpoints_init = False
def on_message(message, data):
    global breakpoints_init
    if message['type'] == 'error':
        sys.stderr.write(str(message) + "\n")
    elif message['type'] == 'send':
        if not breakpoints_init:
            breakpoints_init = True
            schannel_base = int(message['payload'], 16)
            sys.stderr.write("Got schannel base: " + hex(schannel_base)+"\n")
            l = SymLookup(args.schannel_pdb, schannel_base)
            syms =  l.get_sym_addr('SessionKeysHelper')
            sys.stderr.write("Resolved KeyHandlers: " + str(syms) +"\n")
            ret = [hex(s[0]) for s in syms]
            script.post({"type" : "breakpoints", "payload": "|".join(ret)})
        else:
            print(message['payload'])
            if args.local_keylog is not None:
                args.local_keylog.write(message['payload']+"\n")
                args.local_keylog.flush()
script.on('message', on_message)
script.load()
sys.stdin.read()
