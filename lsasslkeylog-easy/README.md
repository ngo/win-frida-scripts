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
