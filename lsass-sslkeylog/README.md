## Requirements:

1. [pdbparse](https://github.com/moyix/pdbparse/)
2. [frida](frida.re)
3. channel.dll for your version of windows (copy from system32)

## Running

1. `frida-server.exe -l 0.0.0.0` on windows machine
2. `./lsasslkeylog.py -H windows.machine.addr --schannel-dll path/to/local/schannel.dll --remote-keylog 'C:\keylog.log' --local-keylog keylog.log`
