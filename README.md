#Anubis v1.1.2

Anubis為萬能封包產生器，支援所有層開始的Socket，與一般封包產生器不同的是大多參數可以利用保留字代替，所有封包組態檔以JSON格式讀入。

</br>

Anubis is a powerful packet generator. Support any layer socket from TCP/IP layers. Different from other packet generator, you can replace most parameter with reserved word. All packet configuration is using JSON format file.

<img src="Anubis.png" width = "300" height = "300">

> 只有在OS X和CentOS上測試，Windows版本請見[這裡](Win32/)。

</br>

> Test on OS X and CentOS only, [Windows version](Win32/).

##Supported protocol
* [```"Ethernet"```](Document/Ethernet.md)
* [```"ARP"```](Document/ARP.md)
* [```"RARP"```](Document/ARP.md)
* [```"Wake-On-LAN"```](Document/WOL.md)
* [```"IPv4"```](Document/IPv4.md)
* [```"IPv4 Options"```](Document/IPv4.md)
* [```"UDP"```](Document/UDP.md)
* [```"TCP"```](Document/TCP.md)
* [```"TCP Options"```](Document/TCP.md)
* [```"ICMPv4 Echo/Request"```](Document/ICMPv4.md)
* [```"ICMPv4 Time Exceeded"```](Document/ICMPv4.md)
* [```"ICMPv4 Destination Unreachable"```](Document/ICMPv4.md)
* [```"ICMPv4 Redirect"```](Document/ICMPv4.md)
* [```"RIPv1/RIPv2"```](Document/RIP.md)
* [```"SSDP"```](Document/Message.md)
* [```"HTTP"```](Document/Message.md)
* [```"DHCPv4"```](Document/DHCPv4.md)
* [```"DHCPv4 Options"```](Document/DHCPv4.md)
* [```"SSL/TLS"```](Document/Socket-Configuration.md)
* [```"Other"```](Document/Other.md)

##Library Dependency
* [libpcap-1.7.4](http://www.tcpdump.org/)
* [libnet-1.2-rc3](https://sourceforge.net/projects/libnet-dev/)
* [libdnet-1.12](https://github.com/dugsong/libdnet/)
* [openssl-1.0.2h](https://www.openssl.org/)
* [json-parser-1.1.0](https://github.com/udp/json-parser)(Built in.)

##Parameter
* ```{}```：表示是一組的參數，只有該組內的參數能夠同時出現。
* ```<>```：表示在該組內是必要參數。
* ```[]```：表示在該處內是可選參數。

</br>

* ```{}```: A group of parameters. The parameters can appear at the same time in the group.
* ```<>```: The parameter is required.
* ```[]```: The parameter is optional.

###Packet injection
* 最主要建構封包功能。
* ```-f filename```、```--filename Filename```：Filename為JSON組態檔檔名。
* ```-a```、```-asynchronous```：所有Socket同時進行。

</br>

* Main function of build packet。
* ```-f filename```、```--filename Filename```: Filename is the JSON configuration filename.
* ```-a```、```-asynchronous```: All Sockets process at the same time.

###IP fragment offset
* 當封包大小超過MTU時，會被切割大小再送出，該功能能夠輔助計算各個被切割封包表頭欄位該填入數值(```"Data-link"```和```"Network"```的```"Socket-type"```需要手動填入)。
* ```-F```、```--fragment Data length```：IP的payload大小，當使用該參數必須使用```-M```、```--MTU```參數，而```-l```、```--ip-header-length```可有可無。
* ```-M```、```--MTU MTU```：同```-F```、```--fragment```。
* ```-l```、```--ip-header-length```：同```-F```、```--fragment```，預設值20，範圍必須為20-60且為4的倍數。

</br>

* When packet size is larger than MTU, it will be fragmented. The aid function can calculate field value in each packet. (```"Socket-type"``` is ```"Data-link"``` and ```"Network"``` need manually fill.)
* ```-F```、```--fragment Data length```: The size of IP payload. The parameter is required with ```-M```、```--MTU```. ```--ip-header-length``` is optional.
* ```-M```、```--MTU MTU```: Same as ```-F```、```--fragment```.
* ```-l```、```--ip-header-length```: Same as ```-F```、```--fragment```. Default is 20, range is 20-60 and must be times of 4.

###List devices
* 列出所有可用的網路卡。
* ```-i [device]```、```--list-devices [device]```：列出所有可用的網路卡，後面可加上特定網卡。

</br>

* List all available interface.
* ```-i [device]```、```--list-devices [device]```: List all available interface. Can specify an interface.

###Output
* 操控一些輸出結果方式。
* ```-t```、```--disable-timestamp```：輸出不會有時戳。
* ```-o```、```--output-filename```：將stdout輸出導向檔案。
* ```-e```、```--error-filename```：將stderr輸出導向檔案。
* ```-v```、```--verbose```：顯示詳細資訊。

</br>

* Output configuration.
* ```-t```、```--disable-timestamp```: Output without timestamp.
* ```-o```、```--output-filename```: Redirect stdout to file.
* ```-e```、```--error-filename```: Redirect stderr to file.
* ```-v```、```--verbose```: Verbose mode.

###Others
* ```--version```：顯示版本資訊。
* ```-h```、```--help```：顯示參數使用方式。

</br>

* ```--version```: Show version.
* ```-h```、```--help```: Show Anubis usage.

##Document
* 封包組態方式文件在[這裡](Document/Socket-Configuration.md)。

</br>

* Packet configuration [document](Document/Socket-Configuration.md).

## Support
* [Image Source](https://www.iconfinder.com/iconsets/windows-8-metro-style).
