# Getting schannel secrets from lsass memory

## Installation

You'll need to install the frida.exe tool, see [the instructions on frida repo](https://github.com/frida/frida#1-install-from-prebuilt-binaries). I recommend installing using pip. Remember that frida only supports python 3.

You'll also need to install [Wireshark](https://www.wireshark.org/).

## Usage

1. Download keylog.js;
2. Open an administrative console and run: `\path\to\frida.exe --no-pause lsass.exe -l \path\to\keylog.js`;
3. Run wireshark and start a traffic capture;
4. Make some TLS traffic (e.g. connect to an RDP, use Invoke-WebRequest from powershell or open a web page in IE);
5. Make sure that `C:\keylog.log` starts to fill up with some keys, the path can be changed in `keylog.js`
6. In Wireshark, go to `Edit->Preferences->Protocols->TLS` and enter `C:\keylog.log` in `(Pre)-Master-Secret log filename`;
7. Watch as all of the traffic is decrypted in real-time.


## Feedback, contacts

Feel free to open issues and/or send emails to ngo at solidlab.ru

## Windows 11 note

As pointed out by https://github.com/l-o-l, in windows 11 by default lsass.exe would crash when hooking with frida.
To mitigate this, the following actions must be performed:

1. Go to `settings->privacy & security->windows security->app&browser control->exploit protection settings`.
2. Create a new entry under `program settings` for lsass.exe, override `hardware-enforced stack protection` (should be set to off).

## AV/EDR products note

As getting a handle of  lsass.exe and/or accessing its memory is a part of many post-exploitation techniques, many antivirus products may either flag this activity as malicious or employ various protections for lsass.exe. If frida cannot attach to lsass.exe even running as admin (you can get an Access Denied error, `WriteProcessMemory returned 0x00000005` or similar), please be sure to check and disable all LSA protections. This is known e.g. to cause problems with Avast, see https://github.com/ngo/win-frida-scripts/issues/4, and Kaspersky is also known to block access to lsass.exe. A basic check is to try creating a memory dump of lsass.exe using Task Manager (as admin). If this does not succeed, there is some sort of lsass protection in place that should be disabled in order to be able to use frida.
