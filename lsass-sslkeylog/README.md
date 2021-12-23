## Requirements:

1. [pdbparse](https://github.com/moyix/pdbparse/)
2. [frida](frida.re)
3. channel.dll for your version of windows (copy from system32)

## Running

1. `frida-server.exe -l 0.0.0.0` on windows machine
2. `./lsasslkeylog.py -H windows.machine.addr --schannel-dll path/to/local/schannel.dll --remote-keylog 'C:\keylog.log' --local-keylog keylog.log`


## Windows 11 note

As pointed out by https://github.com/l-o-l, in windows 11 by default lsass.exe would crash when hooking with frida.
To mitigate this, the following actions must be performed:

1. Go to `settings->privacy & security->windows security->app&browser control->exploit protection settings`.
2. Create a new entry under `program settings` for lsass.exe, override `hardware-enforced stack protection` (should be set to off).
