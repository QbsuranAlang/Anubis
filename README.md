#Anubis v1.0

Anubis為萬能封包產生器，支援所有層開始的Socket，與一般封包產生器不同的是大多參數可以利用保留字代替，所有封包組態檔以JSON格式讀入。

Anubis is a powerful packet generator. Support any layer socket from TCP/IP layers. Different from other packet generator, you can replace most parameter with reserved word. All packet configuration is using JSON format file.

<img src="Anubis.png" width = "300" height = "300">

> 只有在OS X和CentOS上測試。

##Library Dependency
* [json-parser-1.1.0](https://github.com/udp/json-parser)
* [libpcap-1.7.4](http://www.tcpdump.org/)
* [libnet-1.2-rc3](https://sourceforge.net/projects/libnet-dev/)
* [libdnet-1.12](https://github.com/dugsong/libdnet/)
* [openssl-1.0.2h](https://www.openssl.org/)

##Parameter
* ```{}```：表示是一組的參數，只有該組內的參數能夠同時出現。
* ```<>```：表示在該組內是必要參數。
* ```[]```：表示在該處內是可選參數。

###Packet injection
* 最主要建構封包功能。
* ```-f filename```、```--filename Filename```：filename為JSON組態檔檔名。
* ```-a```、```-asynchronous```：所有Socket同時進行。

###IP fragment offset
* 當封包大小超過MTU時，會被切割大小再送出，該功能能夠輔助計算各個被切割封包表頭欄位該填入數值(```"Data-link"```和```"Network"```的```"Socket-type"```需要手動填入)。
* ```-F```、```--fragment Data length```：可以計算當IP的payload大於MTU大小切割封包時，需要填入資訊，當使用該參數必須使用```-M```、```--MTU```參數，而```-l```、```--ip-header-length```可有可無。
* ```-M```、```--MTU MTU```：同```-F```、```--fragment```。
* ```-l```、```--ip-header-length```：同```-F```、```--fragment```，預設值20，範圍必須為20-60且為4的倍數。

###List devices
* 列出所有可用的網路卡
* ```-i [device]```、```--list-devices [device]```：列出所有可用的網路卡，後面可加上特定網卡。

###Output
* 操控一些輸出結果方式
* ```-t```、```--disable-timestamp```：輸出不會有時戳。
* ```-o```、```--output-filename```：將stdout輸出導向檔案。
* ```-e```、```--error-filename```：將stderr輸出導向檔案。
* ```-v```、```--verbose```：verbose mode。

###Others
* ```--version```：顯示版本資訊。
* ```-h```、```--help```：顯示參數使用方式。

##Configuration principle
1. 在```"Template"```目錄下有範例。
2. 所有保留字的欄位都是**不區分大小寫(case insensitive)**，所有的整數都是使用**無號(unsigned)**解析。
3. 在JSON組態檔中，可以使用C style註解```/**/```或C++ style註解```//```。
4. 封包欄位要由下往上封裝，所以```"Sequence"```中的```"Send Packet"```必須是陣列。
5. ```"Option"```是指整著Socket的選項，```"Packet Option"```則是個別封包的選項，所以有些選項會相同。
6. ```Socket-type```如果使用```"Data-link"```，表示連```Ethernet```的部分也要手動填入，使用```"Network"```則```Ethernet```部分不能填入。
7. 一般協定表頭是使用object，而協定的Options使用array。
8. ```"Receive Packet"```只有```"Packet Option"```。

```
[
    {
        "_comment": "註解",
        "Socket-type": "Socket類型",
        "Option": {
            選項
        },
        "Sequence": [
            {
                "Send Packet": [
                    {
                        表頭1
                    },
                    {
                        表頭2
                    },
                    ...

                    {
                        "Packet Option": {
                            選項
                        }
                    }
                ],
                "Receive Packet": [
                    {
                        "Packet Option": {
                            選項
                        }
                    }
                ]
            }
        ]
    }
]
```

##Value types
* ```整數類型(integer)```：可用字串或數字，數字只能為十進位；字串可以是十六進位，能夠用"|"組合，例如: ```"0x0800 | 0x0806"```會解析成: ```0x0806```。
* ```字串類型(string)```：可用```"\uxxxx"```表示unicode，其他逸出自元(escape character)跟JSON相同。
* ```布林類型(boolean)```：可用```"enable"```、```"disable"```、```0```、```1```、0以及1。
* ```二進位類型(binary)```：只能用0或1，有長度限制。
* ```地址類型(address)```：可以使用"Myself"，表示自己的地址訊息，會根據```"Device"```參數取得地址；Broadcast則會填入廣播號碼。
* ```陣列類型(array)```：只能使用```[]```。
* ```物件類型(object)```：只能使用```{}```。
* ```其他類型(others)```：查看該欄位的說明。

###欄位表達式

格式：```"Field name"```(value types, optional/required/depends, default: value): description

> depends：看情況需要。

##Functions
* ```"lookup_mac_address()"```：用來查詢對應的MAC地址，參數只能夠為一個IP地址，例如：```lookup_mac_address(192.168.1.1)```，找不到會先試著送出ARP Request封包一次後再重新嘗試取得，最後失敗會用```"0.0.0.0"```，另外```"224.0.0.0/8"```、```"239.0.0.0/8"```也能夠傳回對應的地址。
* ```"lookup_ip_address()"```：用來查詢對應的IP地址，參數只能夠為一個MAC地址，例如：```lookup_ip_address(1:2:3:4:5:6)```，找不到則會用```"00:00:00:00:00:00"```。
* ```"random_ip_address()"```：隨機產生一個ip地址，不會產生0.0.0.0、廣播地址、群播地址、實驗用地址、私有地址、loopback地址以及0.0.0.0/8。
* ```"random_mac_address()"```：隨機產生一個mac地址，不會產生群播地址和廣播地址。
* ```"random()"```：取得亂數，無參數亂數範圍0-4294967295。參數可以為一個範圍，```random(1-100)```則會產生1-100區間的亂數。其他保留字有：```Well-known```和```Official```，可產生0-1023區間亂數；```Unofficial```和```Registered```可產生1024-49151區間亂數；```Multiple use```、```Dynamic```、 ```Private```和```Ephemeral```可產生49152-65535，```u_int8_t```可產生0-255，```u_int16_t```可產生0-65535，```u_int32_t```可產生0-4294967295（預設值）。
* ```"multicast_address()"```：填入特定協定的群播地址，可用```"RIPv2"```傳回```"224.0.0.9"```、```"SSDP"```傳回```"239.255.255.250"```。
* ```"port()"```：可以直接用協定名稱取得Port number，可用```"HTTP"```傳回```80```、```"HTTPS"```傳回```443```、```"DNS"```傳回```53```、```"SSH"```傳回```22```、```"Telnet"```傳回```23```、```"RIP"```傳回```520```、```"Wake-On-LAN"```(或```"WOL"```)傳回```9```、```"SSDP"```傳回```1900```、```"DHCP-server"```傳回```67```、```"DHCPclient"```傳回```68```。

##Socket option
* ```"_comment"```(string, optional)：註解。
* ```"Socket-type"```(string, required)：可用```"Data-link"```、```"Network"```、```"Transport"```。
* ```""Option""```(object, required)：整個socket的參數。
* ```"Sequence"```(array, required)：個別封包。

##Supported protocol
* ```"Ethernet"```
* ```"ARP"```
* ```"RARP"```
* ```"Wake-On-LAN"```
* ```"IPv4"```
* ```"IPv4 Options"```
* ```"UDP"```
* ```"TCP"```
* ```"TCP Options"```
* ```"ICMPv4 Echo/Request"```
* ```"ICMPv4 Time Exceeded"```
* ```"ICMPv4 Destination Unreachable"```
* ```"ICMPv4 Redirect"```
* ```"RIPv1/RIPv2"```
* ```"SSDP"```
* ```"HTTP"```
* ```"DHCPv4"```
* ```"SSL/TLS"```

###Data-link socket option
* ```"Device"```(string, optional, default: 略過loopback後的第一個有IP地址的device)：要送出封包的device，最好是手動設定。
* ```"Amount"```(integer: 4 bytes, optional, default: 1)：送出輪數(次數)。
* ```"Infinite loop"```(boolean, optional, default: "disable")：是否需要無窮迴圈，如果被設定則```"Amount"```無效果。
* ```"Interval"```(integer: 4 bytes, optional, default: 0)：每輪間隔，單位微秒(microsecond)，預設0表示無間隔。

###Network socket option
* ```"Device"```(string, optional, default: 讓Route table選擇device)：要送出封包的device。
* ```"Amount"```(integer: 4 bytes, optional, default: 1)：送出輪數(次數)。
* ```"Infinite loop"```(boolean, optional, default: "disable")：是否需要無窮迴圈，如果被設定則```"Amount"```無效果。
* ```"Interval"```(integer: 4 bytes, optional, default: 0)：每輪間隔，單位微秒(microsecond)，預設0表示無間隔。

###Transport socket option
* ```"Device"```(string, optional, default: 讓Route table選擇device)：要送出封包的device。
* ```"Amount"```(integer: 4 bytes, optional, default: 1)：送出輪數(次數)。
* ```"Infinite loop"```(boolean, optional, default: "disable")：是否需要無窮迴圈，如果被設定則```"Amount"```無效果。
* ```"Interval"```(integer: 4 bytes, optional, default: 0)：每輪間隔，單位微秒(microsecond)，預設0表示無間隔。
* ```"Destination IP Address"```(address, required)：目的IP地址。
* ```"Protocol"```(string, required)：傳輸層協定，只能用```"IPPROTO_ICMP"```、```"IPPROTO_TCP"```、```"IPPROTO_UDP"```。

###Application socket option
* ```"Device"```(string, optional, default: 讓Route table選擇device)：要送出封包的device。
* ```"Amount"```(integer: 4 bytes, optional, default: 1)：送出輪數(次數)。
* ```"Infinite loop"```(boolean, optional, default: "disable")：是否需要無窮迴圈，如果被設定則```"Amount"```無效果。
* ```"Interval"```(integer: 4 bytes, optional, default: 0)：每輪間隔，單位微秒(microsecond)，預設0表示無間隔。
* ```"Type"```(string, required)：Socket類型，只能是```"SOCK_STREAM"```、```"SOCK_DGRAM"```，```"SOCK_STREAM"```通常使用TCP，```"SOCK_DGRAM"```通常使用UDP。
* ```"Send Timeout"```(integer: 4 bytes, optional, default: 0)：送出超時時間，預設表示會阻塞著直到送出封包，單位毫秒(millisecond)。
* ```"Receive Timeout"```(integer: 4 bytes, optional, default: 0)：接收超時時間，預設表示會阻塞著直到接收封包，單位毫秒(millisecond)。
* ```"Role"```(string, required)：只能是```"Server"```或```"Client"```。

<!--
* ```"Security"```(boolean, optional, default: "disable")：是否使用加密Socket。
-->

####Application type condition(extract option)
如果是```"SOCK_DGRAM"```：

* ```"Muliticast Group"```(array, optional)：每一項只能用字串表示，必須是群播地址（不會檢查），可以使用```"multicast_address()"```，如果使用```"Device"```會造成```"Muliticast Group"```無效。

<!--
如果是```"SOCK_DGRAM"```且```"Security"```是```"enable"```：

* ```"Asynchronous"```(boolean, optional, default: "disable")：處理Client連線是否要非同步處理，預設同步。
-->

如果是```"SOCK_STREAM"```：

* ```"Asynchronous"```(boolean, optional, default: "disable")：處理Client連線是否要非同步處理，預設同步。
* ```"Max Connection"```(integer: 2 bytes, optional, default: 1024)：最大Client連線數。
* ```"Security"```(boolean, optional, default: "disable")：是否使用加密Socket。

####Application role condition(extract option)
如果是```"Server"```：

* ```"Source Port"```(interger 2 bytes, required)：接收特定Port的封包。

> 如果```"Type"```是```"SOCK_DGRAM"```，應先使用```"Receive Packet"```再使用```"Send Packet"```，而```"Send Packet"```的目的IP地址會是```"Receive Packet"```最後收到的IP地址。

如果是```"Server"```且```"Type"```是```"SOCK_STREAM"```且```"Security"```是```"enable"```：

* ```"Method"```(string, optional, depends: "Type")：加密方法，當```"Type"```是```"SOCK_STREAM"```，default: ```"SSLv23"```，只能使用```"SSLv2"```、```"SSLv3"```、```"SSLv23"```、```"TLSv1.0"```、```"TLSv1.1"```、```"TLSv1.2"```，其中```"SSLv23"```表示盡量使用SSL/TLS可用的最高版本。
* ```"Certificate"```(string, depends: "Role")：憑證（公鑰）檔案路徑，必須是PEM格式，如果```"Role"```是```"Server"```，則required。
* ```"Private key"```(string, depends: "Role")：私鑰檔案路徑，必須是PEM格式，如果```"Role"```是```"Server"```，則required。

如果是```"Client"```：

* ```"Destination IP Address"```(address, required)：送至特定IP地址。
* ```"Destination Port"```(interger 2 bytes, required)：送至特定Port。

> 如果```"Type"```是```"SOCK_DGRAM"```，應先使用"Send Packet"再使用"Receive Packet"，而"Receive Packet"的來源Port會是"Send Packet"最後收到的Port。

如果是```"Client"```且```"Type"```是```"SOCK_STREAM"```且```"Security"```是```"enable"```：

* ```"Method"```(string, optional, depends: "Type")：加密方法，當```"Type"```是```"SOCK_STREAM"```，default: ```"SSLv23"```，只能使用```"SSLv2"```、```"SSLv3"```、```"SSLv23"```、```"TLSv1.0"```、```"TLSv1.1"```、```"TLSv1.2"```，其中```"SSLv23"```表示盡量使用SSL/TLS可用的最高版本。
* ```"Certificate"```(string, optional, depends: "Role")：憑證（公鑰）檔案路徑，必須是PEM格式，如果```"Role"```是```"Client"```，則optional。
* ```"Private key"```(string, optional, depends: "Role")：私鑰檔案路徑，必須是PEM格式，如果```"Role"```是```"Client"```，則optional。
* ```"Certificate Information"```(boolean, optional, default: "disable")：是否要顯示Server的憑證資訊。

<!--；當```"Type"```是```"SOCK_DGRAM"```，default: ```"DTLS"```，只能使用```"DTLS"```、```"DTLS1.0"```、```"DTLS1.2"```，其中```"DTLS"```表示盡量使用DTLS可用的最高版本-->

###Send packet comment option
* ```"Amount"```(integer: 4 bytes, optional, default: 1)：送出數量。
* ```"Infinite loop"```(boolean, optional, default: "disable")：是否需要無窮迴圈，如果被設定則```"Amount"```無效果。
* ```"Interval"```(integer: 4 bytes, optional, default: 0)：每個封包間隔，單位微秒(microsecond)，預設0表示無間隔。
* ```"Dump send packet"```(boolean, optional, default: "disable")：送出封包後，是否要將封包解析出來，目前可解析```"Ethernet"```、```"ARP"```、```"Wake-On-LAN"```(Layer 2, over Ethernet)、```"IPv4"```、```"TCP"```、```"UDP"```、```"ICMP"```以及```"Payload"```。

###Receive packet comment option

> 無，除了Application以外，暫無接收封包功能。

####Application send packet(extract option)
* ```"Send Timeout"```(integer: 4 bytes, optional, default: 0)：送出超時時間，預設表示會阻塞著直到送出封包，單位毫秒(millisecond)。
* ```"Send Length"```(integer: 2 bytes, optional, default: 0)：送出封包大小，0表示自動計算。
* ```"Interactive"```(boolean, optional, default: "disable")：封包內容(Message)是否手動輸入，該選項與```"Input from file"```互斥。
* ```"Input from file"```(string, optional, default: NULL)：從檔案讀入封包內容(Message)送出，該選項與```"Interactive"```互斥。

> Interactive(互動模式)是指可以在程式執行階段時，讓使用者用輸入的方式決定送出封包，輸入結束使用EOF訊號表示結束（Windows：Ctrl+Z，*nux：Ctrl+D)；有些特殊字元輸入方式與C語言相同，可用：```'\a'```、```'\b'```、```'\f'```、```'\n'```、```'\r'```、```'\t'```、```'\v'```，如果輸入```'\'```即是反斜線，按下Enter鍵並不會加入換行字元。

####Application receive packet(extract option)
* ```"Amount"```(integer: 4 bytes, optional, default: 1)：送出數量。
* ```"Infinite loop"```(boolean, optional, default: "disable")：是否需要無窮迴圈，如果被設定則```"Amount"```無效果。
* ```"Interval"```(integer: 4 bytes, optional, default: 0)：每個封包間隔，單位微秒(microsecond)，預設0表示無間隔。
* ```"Dump receive packet"```(boolean, optional, default: "disable")：收到封包後，是否要將封包解析出來，目前可解析```"Ethernet"```、```"ARP"```、```"Wake-On-LAN"```(Layer 2, over Ethernet)、```"IPv4"```、```"TCP"```、```"UDP"```、```"ICMP"```以及```"Payload"```。
* ```"Receive Timeout"```(integer: 4 bytes, optional, default: 0)：接收超時時間，預設表示會阻塞著直到接收封包，單位毫秒(millisecond)。
* ```"Read until Timeout"```(boolean, optional, default: "disable")：讀取封包，如果Timeout就結束讀取，會忽略```""Infinite loop"```的設定。
* ```"Output to file"```(string, optional, default: NULL)：將接收到的封包內容(Message)輸出到檔案。

###Payload
* ```"Payload"```(string, optional, default: NULL)：封包最後面攜帶的資料。
* ```"Payload length"```(integer 2 bytes, optional, depends: "Payload"):```"Payload"```長度，如果沒給長度會自動計算；如果```"Payload length"```超過```"Payload"```實際長度，會以```"Payload length"```為主。

> Payload是封包最上層的資料，所以只能出現一次，如果出現兩次以上，會以最後一次為主；如果要使用沒有提供的協定，可以使用Payload的方式建構。

####Payload Example

```
{
    "Payload": {
        "Payload": "This is payload data",
        "Payload Length": 20
    }
}
```

###Raw Data
* ```"Data"```(string, optional, default: NULL)：封包最後面攜帶的資料。
* ```"Data length"```(integer 2 bytes, optional, depends: "Data"):```"Data"```長度，如果沒給長度會自動計算；如果```"Data length"```超過```"Data"```實際長度，會以```"Data length"```為主。

> Raw Data可以出現在任何地方，跟Payload類似，只是沒有出現限制。

####Raw Data Example

```
{
    "Raw Data": {
        "Data": "This is data",
        "Data Length": 12
    }
}
```

###Ethernet header
* ```"Destination MAC Address"```(address, required)：可用```"random_mac_address()"```隨機產生一個地址，也可以使用```"lookup_mac_address()"```來查詢MAC地址。
* ```"Source MAC Address"```(address, optional, default: "myself")：可用```"random_mac_address()"```隨機產生一個地址，也可以使用```"lookup_mac_address()"```來查詢MAC地址。
* ```"Type"```(integer 2 bytes, required)：另外可用```"ETHERTYPE_IP"```、```"ETHERTYPE_ARP"```、```"ETHERTYPE_REVARP"```、```"ETHERTYPE_WOL"```。

####Ethernet Example

```
{
    "Ethernet": {
        "Destination MAC Address": "lookup_mac_address(192.168.1.1)",
        "Source MAC Address": "myself",
        "Type": "ETHERTYPE_ARP"
    }
}
```

###ARP/RARP header
* ```"Hardware Type"```(integer 2 bytes, optional, default: 1)。
* ```"Protocol Type"```(integer 2 bytes, optional, default: "0x0800")。
* ```"Hardware Address Length"```(integer 1 byte, optional, default: 6)。
* ```"Protocol Address Length"```(integer 1 byte, optional, default: 4)。
* ```"Operation"```(integer 2 bytes, required)：另外可用```"ARPOP_REPLY"```、```"ARPOP_REQUEST"```、```"ARPOP_REVREPLY"```、```"ARPOP_REVREQUEST"```。
* ```"Sender Hardware Address"```(address, required)：可用```"random_mac_address()"```隨機產生一個地址，也可以使用```"lookup_mac_address()"```來查詢MAC地址。
* ```"Sender Protocol Address"```(address, required)：可用```"random_ip_address()"```隨機產生一個地址，也可以用```"lookup_ip_address()"```來查詢IP地址。
* ```"Target Hardware Address"```(address, required)：可用```"random_mac_address()"```隨機產生一個地址，也可以使用```"lookup_mac_address()"```來查詢MAC地址。
* ```"Target Protocol Address"```(address, required)：可用```"random_ip_address()"```隨機產生一個地址，也可以用```"lookup_ip_address()"```來查詢IP地址。

> 目前ARP/RARP只支援Ethernet ARP/RARP。

###ARP Example

```
{
    "ARP": {
        "Hardware Type": 1,
        "Protocol Type": "0x0800",
        "Hardware Address Length": 6,
        "Protocol Address Length": 4,
        "Operation": "ARPOP_REQUEST",
        "Sender Hardware Address": "aa:bb:cc:dd:ee:ff",
        "Sender Protocol Address": "random_ip_address()",
        "Target Hardware Address": "Broadcast",
        "Target Protocol Address": "192.168.1.101"
    }
}
```

###Wake-On-LAN header
* ```"Sync Stream"```(other 6 bytes, optional, default: "ff:ff:ff:ff:ff:ff")：以MAC Address方式表示。
* ```"MAC Address"```(address, required)。
* ```"Password"```(address, optional, default: "00:00:00:00:00:00")。

> Wake-On-LAN能夠用在Frame(Layer 2, over Ethernet)或是Message(Layer 5 over UDP)。

####Wake-On-LAN Example

```
{
    "Wake-On-LAN": {
        "Sync Stream": "ff:ff:ff:ff:ff:ff",
        "MAC Address": "lookup_mac_address(192.168.1.100)",
        "Password": "1:2:3:4:5:6"
    }
}
```

###IP(IPv4) header
* ```"Type of Service"```(binary 8 bits, optional, default: "00000000")：長度必須為8。
* ```"Total Length"```(integer 2 bytes, optional, default: "auto")：```"auto"```與0都表示自動計算。
* ```"Identification"```(integer 2 bytes, optional, default: "random(u\_int16\_t)")：可以用```"random()"```取得亂數。
* ```"Flags"```(others 3 bits, optional, default: 0)：只能使用```"IP_RF"```、```"IP_DF"```以及```"IP_MF"```，能夠用"|"組合，例如：```"IP_RF | IP_DF"```。
* ```"Fragment Offset"```(integer 2 bytes, optional, default: 0)。
* ```"Time to Live"```(integer 1 byte, optional, default: 64)。
* ```"Protocol"```(integer 1 byte, required)：另外可使用```"IPPROTO_ICMP"```、```"IPPROTO_UDP"```或```"IPPROTO_TCP"```。
* ```"Header Checksum"```(integer 2 bytes, optional, default: "auto")：```"auto"```與0都表示自動計算。
* ```"Source IP Address"```(address, optional, default: "myself")：可用```"random_ip_address()"```隨機產生一個地址，也可以用```"lookup_ip_address()"```來查詢IP地址，也可以使用Hostname表示，還可以用```"multicast_address()"```來取得特定協定的群播地址。
* ```"Destination IP Address"```(address, required)：可用```"random_ip_address()"```隨機產生一個地址，也可以用```"lookup_ip_address()"```來查詢IP地址，也可以使用Hostname表示，還可以用```"multicast_address()"```來取得特定協定的群播地址。

###IP(IPv4) Example

```
{
    "IP": {
        "Type of Service": "10001001",
        "Total Length": 84,
        "Identification": "random()",
        "Flags": "IP_DF | IP_RF",
        "Fragment Offset": 0,
        "Time to Live": 120,
        "Protocol": "IPPROTO_ICMP",
        "Header Checksum": "auto",
        "Source IP Address": "www.google.com",
        "Destination IP Address": "multicast_address(SSDP)"
    }
}
```

###IPv4 Options
* ```"Type"```(integer 1 byte, required)：可使用```"IPOPT_EOL"```、```"IPOPT_RR"```。

> IPv4 Options必須為4的倍數。

####IPv4 Option IPOPT_RR(Record Route, 7)
* ```"Length"```(integer 1 byte, optional, default: 39)：預設值39-3=36/4=9，9個Route是Record route的最大值，該數值減3後應為4的倍數。
* ```"Pointer"```(integer 1 byte, optional, default: 4)。
* ```"Route1"```(address, optional, default: "0.0.0.0")。
* ```"Route2"```(address, optional, default: "0.0.0.0")。
* ```"Route3"```(address, optional, default: "0.0.0.0")。
* ```"Route4"```(address, optional, default: "0.0.0.0")。
* ```"Route5"```(address, optional, default: "0.0.0.0")。
* ```"Route6"```(address, optional, default: "0.0.0.0")。
* ```"Route7"```(address, optional, default: "0.0.0.0")。
* ```"Route8"```(address, optional, default: "0.0.0.0")。
* ```"Route9"```(address, optional, default: "0.0.0.0")。

####IPv4 Option IPOPT_EOL(End of Line, 0)

> 無

####IPv4 Options Example

```
{
    "IP Options": [
        {
            "Type": "IPOPT_RR",
            "Length": 39,
            "Pointer": 4,
            "Route1": "0.0.0.0",
            "Route2": "0.0.0.0",
            "Route3": "0.0.0.0",
            "Route4": "0.0.0.0",
            "Route5": "0.0.0.0",
            "Route6": "0.0.0.0",
            "Route7": "0.0.0.0",
            "Route8": "0.0.0.0",
            "Route9": "0.0.0.0"
        },
        {
            "Type": "IPOPT_EOL"
        }
    ]
}
```

###UDP header
* ```"Source Port"```(integer 2 bytes, required)：可以用```"random()"```取得亂數，另外可以使用```port()```填入參數。
* ```"Destination Port"```(integer 2 bytes, required)：可以用```"random()"```取得亂數，另外可以使用```port()```填入參數。
* ```"Checksum"```(integer 2 bytes, optional, default: "auto")：```"auto"```與0都表示自動計算。
* ```"Length"```(integer 2 bytess, optional, default: "auto")：```"auto"```與0都表示自動計算。

####UDP Example

```
{
    "UDP": {
        "Source Port": "random(dynamic)",
        "Destination Port": "port(RIP)",
        "Length": "0x8",
        "Checksum": "auto"
    }
}
```

###TCP header
* ```"Source Port"```(integer 2 bytes, required)：可以用```"random()"```取得亂數，另外可以使用```port()```填入參數。
* ```"Destination Port"```(integer 2 bytes, required)：可以用```"random()"```取得亂數，另外可以使用```port()```填入參數。
* ```"Sequence number"```(integer 4 bytes, optional, default: 0)：可以簡寫成```"seq"```。
* ```"Acknowledgment number"```(integer 4 bytes, optional, default: 0)：可以簡寫成```"ack"```。
* ```"Flags"```(others 8 bits, optional, default: 0)：只能使用```"TH_FIN"```、```"TH_SYN"```、```"TH_RST"```、```"TH_PUSH"```、```"TH_ACK"```、```"TH_URG"```、```"TH_ECE"```和```"TH_CWR"```，能夠用"|"組合，例如```"TH_SYN | TH_ACK"```。
* ```"Window"```(integer 2 bytes, optional, default: 0)。
* ```"Checksum"```(integer 2 bytes, optional, default: "auto")：```"auto"```與0都表示自動計算。
* ```"Urgent Pointer"```(integer 2 bytes, optional, default: 0)。

####TCP Example

```
{
    "TCP": {
        "Source Port": "random(dynamic)",
        "Destination Port": "80",
        "Sequence number": "0x12345678",
        "Acknowledgment number": "0x87654321",
        "Flags": "TH_SYN | TH_FIN | TH_PUSH",
        "Window": "0xabcd",
        "Checksum": "auto",
        "Urgent Pointer": "0"
    }
}
```

###TCP Options
* ```"Type"```(integer 1 byte, required)：可使用```"TCPOPT_MAXSEG"```、```"TCPOPT_SACK_PERMITTED"```、```"TCPOPT_WINDOW"```、```"TCPOPT_NOP"```、```"TCPOPT_EOL"```。

> TCP Options必須為4的倍數。

####TCP Option TCPOPT_MAXSEG(Maximum Segment Size, 2)
* ```"Length"```(integer 1 byte, optional, default: 4)。
* ```"MSS Value"```(integer 2 bytes, required)。

###TCP Option TCPOPT\_SACK\_PERMITTED(SACK Permitted, 4)
* ```"Length"```(integer 1 byte, optional, default: 2)。

###TCP Option TCPOPT_WINDOW(Window Scale, 3)
* ```"Length"```(integer 1 byte, optional, default: 3)。
* ```"Shift count"```(integer 1 byte, required)。

###TCP Option TCPOPT_NOP(No Operation, 1)

> 無

###TCP Option TCPOPT_EOL(End of Line, 0)

> 無

####TCP Options Example

```
{
    "TCP Options": [
        {
            "Type": "TCPOPT_MAXSEG",
            "Length": 4,
            "MSS Value": 1460
        },
        {
            "Type": "TCPOPT_SACK_PERMITTED",
            "Length": 2
        },
        {
            "Type": "TCPOPT_WINDOW",
            "Length": 3,
            "Shift count": 7
        },
        {
            "Type": "TCPOPT_EOL"
        }
    ]
}
```

###ICMP(ICMPv4) header
* ```"Type"```(integer 1 byte, required)：另外可用```"ICMP_ECHO"```、```"ICMP_ECHOREPLY"```、```"ICMP_TIMXCEED"```、```"ICMP_UNREACH"```以及```"ICMP_REDIRECT"```。
* ```"Code"```(integer 1 byte, required)：另外可用```"ICMP_TIMXCEED_INTRANS"```、```"ICMP_TIMXCEED_REASS"```、```"ICMP_UNREACH_NET"```、```"ICMP_UNREACH_HOST"```、```"ICMP_UNREACH_PROTOCOL"```、```"ICMP_UNREACH_PORT"```、```"ICMP_UNREACH_NEEDFRAG"```、```"ICMP_UNREACH_SRCFAIL"```、```"ICMP_UNREACH_NET_UNKNOWN"```、```"ICMP_UNREACH_HOST_UNKNOWN"```、```"ICMP_UNREACH_ISOLATED"```、```"ICMP_UNREACH_NET_PROHIB"```、```"ICMP_UNREACH_HOST_PROHIB"```、```"ICMP_UNREACH_TOSNET"```、```"ICMP_UNREACH_TOSHOST"```、```"ICMP_UNREACH_FILTER_PROHIB"```、```"ICMP_UNREACH_HOST_PRECEDENCE"```、```"ICMP_UNREACH_PRECEDENCE_CUTOFF"```、```"ICMP_REDIRECT_NET"```、```"ICMP_REDIRECT_HOST"```、```"ICMP_REDIRECT_TOSNET"```以及```"ICMP_REDIRECT_TOSHOST"```。
* ```"Checksum"```(integer 2 bytes, optional, default: "auto")：```"auto"```與0都表示自動計算。
* ```"Identifier"```(integer 2 bytes, optional, default: 0)：可以用```"random()"```取得亂數。
* ```"Sequence number"```(integer 2 bytes, optional, default: 0)：可以簡寫成```"seq"```，可以用```"random()"```取得亂數。
* ```"Next MTU"```(integer 2 bytes, optional, default: 0)：該欄位會在```"Type="ICMP_UNREACH"```且```"Code"="ICMP_UNREACH_NEEDFRAG"```時才有作用。
* ```"Gateway"```(address, optional, default: "0.0.0.0")。

> 1. 因為ICMP Redirect封包中(最後的)IP表頭後所帶的資料只有8 bytes，如果該資料的有"Checksum"欄位且使用"auto"，則會用那8 bytes計算Checksum。
2.  如果已經使用了ICMP Redirect，不應該再繼續使用"Payload"欄位。

####ICMP(ICMPv4) Example1

```
{
                        "ICMP": {
                            "Type": "ICMP_ECHO",
                            "Code": 0,
                            "Checksum": "auto",
                            "Identifier": "random()",
                            "Sequence number": "random()"
                        }
                    }
```

###ICMP(ICMPv4) Example2

```
{
    "ICMP": {
        "Type": "ICMP_REDIRECT",
        "Code": "ICMP_REDIRECT_HOST",
        "Checksum": "auto",
        "Gateway": "myself"
    }
}
```

###ICMP(ICMPv4) Example3

```
{
    "ICMP": {
        "Type": "ICMP_UNREACH",
        "Code": "ICMP_UNREACH_NEEDFRAG",
        "Checksum": "auto",
        "Next MTU": 123
    }
}
```

###ICMP(ICMPv4) Example4

```
{
    "ICMP": {
        "Type": "ICMP_TIMXCEED",
        "Code": 0,
        "Checksum": "auto"
    }
}
```

###RIP
* ```"Command"```(integer 1 byte, required)：另外可用```"RIPCMD_REQUEST"```、```"RIPCMD_RESPONSE"```、```"RIPCMD_TRACEON"```、```"RIPCMD_TRACEOFF"```、```"RIPCMD_POLL"```以及```"RIPCMD_POLLENTRY"```。
* ```"Version"```(integer 1 byte, required)：另外可用```"RIPVER_0"```、```"RIPVER_1"```以及```"RIPVER_2"```。
* ```"Routing Domain"```(integer 2 bytes, optional, default: 0)：```"RIPVER_2"```使用的，在```"RIPVER_1"```應該為0。
* ```"Route Table Entry"```(array, required)：每項路由訊息陣列，可以簡寫成```"RTE"```。

####RIP Route Table Entry
* ```"Address Family"```(integer 2 bytes, required)：另外可用```AF_INET```。
* ```"Route Tag"```(integer 2 bytes, optional, default: 0)：```"RIPVER_2"```使用的，在```"RIPVER_1"```應該為0。
* ```"IP Address"```(address, required)：可用```"random_ip_address()"```隨機產生一個地址，也可以用```"lookup_ip_address()"```來查詢IP地址，也可以使用Hostname表示，還可以用```"multicast_address()"```來取得特定協定的群播地址。
* ```"Netmask"```(address, required)：可用```"random_ip_address()"```隨機產生一個地址，也可以用```"lookup_ip_address()"```來查詢IP地址，也可以使用Hostname表示，還可以用```"multicast_address()"```來取得特定協定的群播地址。
* ```"Next hop"```(address, optional, default: "0.0.0.0")：```"RIPVER_2"```使用的，在```"RIPVER_1"```應該為0.0.0.0；可用```"random_ip_address()"```隨機產生一個地址，也可以用```"lookup_ip_address()"```來查詢IP地址，也可以使用Hostname表示，還可以用```"multicast_address()"```來取得特定協定的群播地址。
* ```"Metric"```：(integer 4 bytes, required)。

####RIP Example

```
{
    "RIP": {
        "Command": "RIPCMD_RESPONSE",
        "Version": "1",
        "Routing Domain": "0",
        "Route Table Entry": [
            {
                "Address Family": "AF_INET",
                "Route Tag": "0",
                "IP Address": "192.168.1.1",
                "Netmask": "255.255.255.0",
                "Next hop": "0.0.0.0",
                "Metric": 2
            },
            {
                "Address Family": "AF_INET",
                "Route Tag": "0",
                "IP Address": "192.168.1.1",
                "Netmask": "255.255.255.0",
                "Next hop": "0.0.0.0",
                "Metric": 2
            }
        ]
    }
}
```

###Internet Message Format(Request)
* ```"Method"```(string, required)。
* ```"URL"```(string, required)。
* ```"Version"```(string, optional, default: "HTTP/1.1")。

> "Request"需要為object。

###Internet Message Format(Response)
* ```"Version"```(string, optional, default: "HTTP/1.1")。
* ```"Status Code"```(integer 4 bytes, depends: "Phrase")。
* ```"Phrase"```(string, depends: "Status Code")。

> "Response"需要為object，"Status Code"和"Phrase"如果只填入其中一個，會自動互相填入另一個。

####參考對應表
```
100, "Continue"
101, "Switching Protocols"
102, "Processing"
200, "OK"
201, "Created"
202, "Accepted"
203, "Non-Authoritative Information"
204, "No Content"
205, "Reset Content"
206, "Partial Content"
207, "Multi-Status"
208, "Already Reported"
226, "IM Used"
300, "Multiple Choices"
301, "Moved Permanently"
302, "Found"
303, "See Other"
304, "Not Modified"
305, "Use Proxy"
306, "Switch Proxy"
307, "Temporary Redirect"
308, "Permanent Redirect"
400, "Bad Request"
401, "Unauthorized"
402, "Payment Required"
403, "Forbidden"
404, "Not Found"
405, "Method Not Allowed"
406, "Not Acceptable"
407, "Proxy Authentication Required"
408, "Request Timeout"
409, "Conflict"
410, "Gone"
411, "Length Required"
412, "Precondition Failed"
413, "Payload Too Large"
414, "URI Too Long"
415, "Unsupported Media Type"
416, "Range Not Satisfiable"
417, "Expectation Failed"
418, "I'm a teapot"
421, "Misdirected Request"
422, "Unprocessable Entity"
423, "Locked"
424, "Failed Dependency"
426, "Upgrade Required"
428, "Precondition Required"
429, "Too Many Requests"
431, "Request Header Fields Too Large"
451, "Unavailable For Legal Reasons"
500, "Internal Server Error"
501, "Not Implemented"
502, "Bad Gateway"
503, "Service Unavailable"
504, "Gateway Timeout"
505, "HTTP Version Not Supported"
506, "Variant Also Negotiates"
507, "Insufficient Storage"
508, "Loop Detected"
510, "Not Extended"
511, "Network Authentication Required"

//Unofficial codes
103, "Checkpoint"
420, "Method Failure"
420, "Enhance Your Calm"
450, "Blocked by Windows Parental Controls"
498, "Invalid Token"
499, "Token Required"
499, "Request has been forbidden by antivirus"
509, "Bandwidth Limit Exceeded"
530, "Site is frozen"
440, "Login Timeout"
449, "Retry With"
451, "Redirect"
444, "No Response"
495, "SSL Certificate Error"
496, "SSL Certificate Required"
497, "HTTP Request Sent to HTTPS Port"
499, "Client Closed Request"
520, "Unknown Error"
521, "Web Server Is Down"
522, "Connection Timed Out"
523, "Origin Is Unreachable"
524, "A Timeout Occurred"
525, "SSL Handshake Failed"
526, "Invalid SSL Certificate"
0, "Undefined"
```

> https://zh.wikipedia.org/wiki/HTTP%E7%8A%B6%E6%80%81%E7%A0%81

###Internet Message Format(Field)
* ```"Keys"```(array, required)：只能使用字串表示。
* ```"Values"```(array, required)：只能使用字串表示。

> "Keys"和"Values"互相搭配使用，陣列數量必須相同。

###SSDP

> SSDP使用Internet Message Format(與HTTP相同)，都使用兩個object："Request"或"Response"以及"Field"，其中"Request"和"Response"同時只能存在一個。

####SSDP Example

```
{
    "SSDP": {
        "Request": {
            "Method": "M-SEARCH",
            "URL": "*",
            "Version": "HTTP/1.1"
        },
        "Field": {
            "Keys": [
                "HOST",
                "MAN",
                "MX",
                "ST"
            ],
            "Values": [
                "239.255.255.250:1900",
                "\"ssdp:discover\"",
                "2",
                "ssdp:all"
            ]
        }
    }
}
```

###HTTP

> HTTP使用Internet Message Format，使用兩個object："Request"或"Response"以及"Field"，其中"Request"和"Response"同時只能存在一個。

####HTTP Example

```
{
    "HTTP": {
        "Request": {
            "Method": "GET",
            "URL": "/",
            "Version": "HTTP/1.1"
        },
        "Field": {
            "Keys": [
                "Host",
                "Connection",
                "Accept",
                "Upgrade-Insecure-Requests",
                "User-Agent",
                "Accept-Encoding",
                "Accept-Language"
            ],
            "Values": [
                "translate.google.com.tw",
                "keep-alive",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "1",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36",
                "gzip, deflate, sdch",
                "zh-TW,zh;q=0.8,en-US;q=0.6,en;q=0.4"
            ]
        }
    }
}
```

###DHCPv4 header
* ```"Operation Code"```(integer: 1 byte, required)：另外可用```"DHCP_REQUEST"```、```"DHCP_REPLY"```。
* ```"Hardware Address Type"```(integer: 1 byte, optional, default: "0x1")：預設0x1表示乙太網路。
* ```"Hardware Address Length"```(integer: 1 byte, optional, default: 6)。
* ```"Hops"```(integer: 1 byte, optional, default: 0)：proxy servers使用。
* ```"Transaction ID"```(integer: 4 bytes, optional, default: "random(u\_int16\_t)")：可以用```"random()"```取得亂數。
* ```"Seconds"```(integer: 2 bytes, optinoal, default: 0)：目前section所花的時間。
* ```"Broadcast Flags"```(boolean, optional, default: "disable")："enable"是Unicast，BOOTP不使用。
* ```"Client IP Address"```(address, optional, default: "0.0.0.0")。
* ```"Your IP Address"```(address, optional, default: "0.0.0.0")：Client IP address。
* ```"Server IP Address"```(address, optional, default: "0.0.0.0")：Next server IP address。
* ```"Gateway IP Address"```(address, optional, default: "0.0.0.0")：Relay agent IP address。
* ```"Client MAC Address"```(address, optional, default: "myself")。
* ```"Server Hostname"```(string, optional, default: NULL)。
* ```"Boot File Name"```(string, optional, default: NULL)。

####DHCPv4 Example

```
{
    "DHCP": {
        "Operation Code": "DHCP_REQUEST",
        "Hardware Address Type": "0x1",  
        "Hardware Address Length": "6",
        "Hops": 0,
        "Transaction ID": "0x87654321",
        "Seconds": 0,
        "Broadcast Flags": "disable", 
        "Client IP Address": "0.0.0.0",
        "Your IP Address": "0.0.0.0",
        "Server IP Address": "0.0.0.0",
        "Gateway IP Address" : "0.0.0.0",
        "Client MAC Address": "myself",
        "Server Hostname": "DHCP server hostname",
        "Boot File Name": "Boot filename"
    }
}
```

> DHCP封包（包含Option）最小需要300 bytes，所以填寫UDP和IP長度欄位時需要注意（RFC1542），或者直接使用"auto"。

###DHCPv4 Options
* ```"Type"```(integer: 1 byte, required)：可使用```"DHCP_MESSAGETYPE"```、```"DHCP_CLIENTID"```、```"DHCP_REQUESTED_IP_ADDRESS"```、```"DHCP_PARAMREQUEST"```、```"DHCP_PAD"```、```"DHCP_SERVER"```、```"DHCP_LEASETIME"```、```"DHCP_SUBNETMASK"```、```"DHCP_ROUTER"```、```"DHCP_DNS_SERVER"```、```"DHCP_NTP_SERVER"```、```"DHCP_RENEWTIME"```、```"DHCP_REBINDTIME"```、```"DHCP_HOSTNAME"```。

####DHCPv4 Option DHCP_MESSAGETYPE(Message Type, 53)
* ```"Length"```(integer: 1 byte, optinoal, default: 1)。
* ```"Message"```(integer: 1 byte, required)：另外可用```"DHCP_MSGDISCOVER"```、```"DHCP_MSGOFFER"```、```"DHCP_MSGREQUEST"```、```"DHCP_MSGDECLINE"```、```"DHCP_MSGACK"```、```"DHCP_MSGNACK"```、```"DHCP_MSGINFORM"```。

####DHCPv4 Option DHCP_CLIENTID(Client ID, 61)
* ```"Length"```(integer: 1 byte, optional, default: 7)：```"Type"```(1) + Mac address(6) = 7。
* ```"Hardware Address Type"```(integer: 1 byte, optional, default: "0x1")：預設0x1表示乙太網路。
* ```"Client Hardware Address"```(address, optional, default: "myself")。

####DHCPv4 Option DHCP\_REQUESTED\_SERVER(Requested IP Address, 50)
* ```"Length"```(integer: 1 byte, optional, default: 4)。
* ```"Requested IP Address"```(address, optional, default: "0.0.0.0")。

####DHCPv4 Option DHCP_PARAMREQUEST(Parameter, 55)
* ```"Length"```(integer: 1 byte, optional, depends: "List")：預設為```"List"```長度。
* ```"List"```(array, required)：陣列內除了整數以外，能夠使用```"DHCP_SUBNETMASK"```、```"DHCP_ROUTER"```、```"DHCP_DNS_SERVER"```、```"DHCP_NTP_SERVER"```。

####DHCPv4 Option DHCP_PAD(Padding, 0)

> 無。

####DHCPv4 Option DHCP_END(End, 255)

> 無。

####DHCPv4 Option DHCP_SERVER(DHCP Server Identifier, 54)
* ```"Length"```(integer: 1 byte, optional, default: 4)。
* ```"Server IP Address"```(address, required)。

####DHCPv4 Option DHCP_SUBNETMASK(Subnet mask, 1)
* ```"Length"```(integer: 1 byte, optional, default: 4)。
* ```"Netmask"```(address, required)。

####DHCPv4 Option DHCP_ROUTER(Router, 3)
* ```"Length"```(integer: 1 byte, optional, default: 4)。
* ```"Router IP Address"```(address, required)。

####DHCPv4 Option DHCP\_DNS\_SERVER(DNS Server, 6)
* ```"Length"```(integer: 1 byte, optional, default: 4)。
* ```"DNS IP Address"```(address, required)。

####DHCPv4 Option DHCP\_NTP\_SERVER(NTP Server, 42)
* ```"Length"```(integer: 1 byte, optional, default: 4)。
* ```"NTP IP Address"```(address, required)。

####DHCPv4 Option DHCP_RENEWTIME(Renewal Time, 58)
* ```"Length"```(integer: 1 byte, optional, default: 4)。
* ```"Time"```(integer: 4 bytes, required)：單位秒。

####DHCPv4 Option DHCP_REBINDTIME(Rebind Time, 69)
* ```"Length"```(integer: 1 byte, optional, default: 4)。
* ```"Time"```(integer: 4 bytes, required)：單位秒。

####DHCPv4 Option DHCP_LEASETIME(IP Address Lease Time, 51)
* ```"Length"```(integer: 1 byte, optional, default: 4)。
* ```"Time"```(integer: 4 bytes, required)：單位秒。

####DHCPv4 Option DHCP_HOSTNAME(Hostname, 12)
* ```"Length"```(integer: 1 byte, optional, depends: "Hostname")：預設```"Hostname"```長度。
* ```"Hostname"```(string, required)。

####DHCPv4 Options Example1
```
{
    "DHCP Options": [
        {
            "Type": "DHCP_MESSAGETYPE",
            "Length": 1,
            "Message": "DHCP_MSGREQUEST"
        },
        {
            "Type": "DHCP_PARAMREQUEST",
            "Length": 4,
            "List": [
                "DHCP_SUBNETMASK",
                "DHCP_ROUTER",
                "DHCP_DNS_SERVER",
                "DHCP_NTP_SERVER"
            ]
        },
        {
            "Type": "DHCP_CLIENTID",
            "Length": 7,
            "Hardware Address Type": "0x1",
            "Client Hardware Address": "myself"
        },
        {
            "Type": "DHCP_REQUESTED_IP_ADDRESS",
            "Length": 4,
            "Requested IP Address": "0.0.0.0"
        },
        {
            "Type": "DHCP_HOSTNAME",
            "Length": 13,
            "Hostname": "TU-MBR-Retina"
        },
        {
            "Type": "DHCP_PAD"
        },
        {
            "Type": "DHCP_END"
        }
    ]
}
```

####DHCPv4 Options Example2
```
{
    "DHCP Options": [
        {
            "Type": "DHCP_MESSAGETYPE",
            "Length": 1,
            "Message": "DHCP_MSGOFFER"
        },
        {
            "Type": "DHCP_SERVER",
            "Length": 4,
            "Server IP Address": "myself"
        },
        {
            "Type": "DHCP_LEASETIME",
            "Length": 4,
            "Time": 21600
        },
        {
            "Type": "DHCP_SUBNETMASK",
            "Length": 4,
            "Netmask": "255.255.255.0"
        },
        {
            "Type": "DHCP_ROUTER",
            "Length": 4,
            "Router IP Address": "192.168.1.1"
        },
        {
            "Type": "DHCP_DNS_SERVER",
            "Length": 4,
            "DNS IP Address": "192.168.1.1"
        },
        {
            "Type": "DHCP_NTP_SERVER",
            "Length": 4,
            "NTP IP Address": "192.168.1.1"
        },
        {
            "Type": "DHCP_RENEWTIME",
            "Length": 4,
            "Time": 1800
        },
        {
            "Type": "DHCP_REBINDTIME",
            "Length": 4,
            "Time": 1800
        },
        {
            "Type": "DHCP_END"
        }
    ]
}
```



