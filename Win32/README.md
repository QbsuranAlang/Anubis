#Anubis v1.1.2 (Windows)

Windows版本目前不穩定，大致上幾乎所有功能正常。

>懶得修改。

##Usage

1. 安裝[Winpcap](Dependencies/WpdPack/WinPcap_4_1_3.exe)。
2. 複製[目錄](Release/)內*.dll到C:\Windows內。
3. 執行[Anubis](Release/Anubis.exe)，需要Administrator權限。

##Bugs
1. Application Socket的UDP無法廣播。
2. Transport Socket的TCP無法使用。
3. Receive packet option中的Timeout似乎無法使用。

###Bug 1

似乎在大多數Windows 7以上系統皆無法使用。

> [See here 1](http://stackoverflow.com/questions/4615275/udp-broadcast-in-windows-7-does-it-work)

> [See here 2](http://serverfault.com/questions/72112/how-to-alter-the-global-broadcast-address-255-255-255-255-behavior-on-windows)

###Bug 2 (Limitations on Raw Sockets)

Windows對於Raw socket有一些限制，Bugs的第二點就是因為此限制所以無法使用。

```
Limitations on Raw Sockets

On Windows 7, Windows Vista, Windows XP with Service Pack 2 (SP2), and Windows XP with Service Pack 3 (SP3), the ability to send traffic over raw sockets has been restricted in several ways:
* TCP data cannot be sent over raw sockets.
* UDP datagrams with an invalid source address cannot be sent over raw sockets. The IP source address for any outgoing UDP datagram must exist on a network interface or the datagram is dropped. This change was made to limit the ability of malicious code to create distributed denial-of-service attacks and limits the ability to send spoofed packets (TCP/IP packets with a forged source IP address).
* A call to the bind function with a raw socket for the IPPROTO_TCP protocol is not allowed.

Note  The bind function with a raw socket is allowed for other protocols (IPPROTO_IP, IPPROTO_UDP, or IPPROTO_SCTP, for example).
```

> [Limitations on Raw Sockets](https://msdn.microsoft.com/en-us/library/windows/desktop/ms740548(v=vs.85).aspx#Limitations_on_Raw_Sockets)