#Socket Configuration

Anubis socket 組態和範例。

</br>

Socket configuration and examples.

##Socket configuration principle
1. 在**[Socket-Template](Socket-Template/)**目錄下有範例。
2. 所有保留字的欄位都是**不區分大小寫(case insensitive)**，所有的整數都是使用**無號(unsigned)**解析。
3. 在JSON組態檔中，可以使用C style註解```/**/```或C++ style註解```//```。
4. 封包欄位要由下往上封裝，所以```"Sequence"```中的```"Send Packet"```必須是陣列。
5. ```"Option"```是指整著Socket的選項，```"Packet Option"```則是個別封包的選項，所以有些選項會相同。
6. ```Socket-type```如果使用```"Data-link"```，表示連```Ethernet```的部分也要手動填入，使用```"Network"```則```Ethernet```部分不能填入。
7. 一般協定表頭是使用object，而協定的Options使用array。
8. ```"Receive Packet"```只有```"Packet Option"```。

</br>

1. Examples in directory **[Socket-Template](Socket-Template/)**.
2. All reserved word are **case insensitive**. All integer are **unsigned**.
3. C style comment ```/**/``` and C++ style comment ```//``` are available in JSON configuration file.
4. Build packet is from bottom to top. ```"Send Packet"``` in ```"Sequence"``` must be an array.
5. ```"Option"``` is whole socket option. ```"Packet Option"``` is each packet option. Some option is the same.
6. If ```Socket-type``` is ```"Data-link"``` which mean ```Ethernet``` is manually fill. If is ```"Network"```, ```Ethernet``` must can't be appear.
7. General protocol is an object and protocol options is an array.
8. ```"Receive Packet"``` only have ```"Packet Option"```.

```
[
    {
        "_comment": "註解/comment",
        "Socket-type": "Socket類型/socket type",
        "Option": {
            選項/option
        },
        "Sequence": [
            {
                "Send Packet": [
                    {
                        表頭1/header 1
                    },
                    {
                        表頭2/header 2
                    },
                    ...

                    {
                        "Packet Option": {
                            選項/option
                        }
                    }
                ],
                "Receive Packet": [
                    {
                        "Packet Option": {
                            選項/option
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
* ```地址類型(address)```：可以使用```"Myself"```，表示自己的地址訊息，會根據```"Device"```參數取得地址；```"Default-Route"```會填入預設閘道；```"Broadcast"```則會填入廣播號碼，另外如果是IP地址還可以使用主機名稱代替。
* ```陣列類型(array)```：只能使用```[]```。
* ```物件類型(object)```：只能使用```{}```。
* ```其他類型(others)```：查看該欄位的說明。

</br>

* ```Integer```: String and number are available, number is decimal. String can be hexadecimal. "|" is available. Example: ```"0x0800 | 0x0806"``` is parsed ```0x0806```.
* ```String```: ```"\uxxxx"``` is available which mean unicode, escape character is same as JSON.
* ```Boolean```: ```"enable"```, ```"disable"```, ```0```, ```1```, 0 and 1 are available.
* ```Binary```: 0 or 1 only, length is limited.
* ```Address```: ```"Myself"``` means self address information according to ```"Device"```. ```"Default-Route"``` will fill default gateway. ```"Broadcast"``` means broadcast address. If it is IP address, hostname is available.
* ```Array```: ```[]``` only.
* ```Object```: ```{}``` only.
* ```Others```: Check the feild Explanation.

###Packet field expression

格式：```"欄位名稱"```(數值類型, 可選的/必須的/看情況, 預設: 預設值): 描述。

</br>

Format: ```"Field name"```(value types, optional/required/depends, default: value): description.

##Functions
* ```"lookup_mac_address()"```：用來查詢對應的MAC地址，參數只能夠為一個IP地址，例如：```lookup_mac_address(192.168.1.1)```，找不到會先試著送出ARP Request封包一次後再重新嘗試取得；另外```"224.0.0.0/8"```、```"239.0.0.0/8"```也能夠傳回對應的地址。
* ```"lookup_ip_address()"```：用來查詢對應的IP地址，參數只能夠為一個MAC地址，例如：```lookup_ip_address(1:2:3:4:5:6)```，找不到則會用```"0.0.0.0"```。
* ```"random_ip_address()"```：隨機產生一個ip地址，不會產生0.0.0.0、廣播地址、群播地址、實驗用地址、私有地址、loopback地址以及0.0.0.0/8。
* ```"random_mac_address()"```：隨機產生一個mac地址，不會產生群播地址和廣播地址。
* ```"random()"```：取得亂數，無參數亂數範圍0-4294967295。參數可以為一個範圍，```random(1-100)```則會產生1-100區間的亂數。其他保留字有：```Well-known```和```Official```，可產生0-1023區間亂數；```Unofficial```和```Registered```可產生1024-49151區間亂數；```Multiple use```、```Dynamic```、```Private```和```Ephemeral```可產生49152-65535，```u_int8_t```可產生0-255，```u_int16_t```可產生0-65535，```u_int32_t```可產生0-4294967295（預設值）。
* ```"multicast_address()"```：傳回特定協定的群播地址，可用```"RIPv2"```傳回```"224.0.0.9"```、```"SSDP"```傳回```"239.255.255.250"```。
* ```"port()"```：可以直接用協定名稱取得Port number，可用```"HTTP"```傳回```80```、```"HTTPS"```傳回```443```、```"DNS"```傳回```53```、```"SSH"```傳回```22```、```"Telnet"```傳回```23```、```"RIP"```傳回```520```、```"Wake-On-LAN"```（或```"WOL"```）傳回```9```、```"SSDP"```傳回```1900```、```"DHCP-server"```傳回```67```、```"DHCP-client"```傳回```68```。

</br>

* ```"lookup_mac_address()"```: Lookup corresponding MAC address. Parameter is an IP address. Example: ```lookup_mac_address(192.168.1.1)```. If is not found, send an ARP request and retry again. ```"224.0.0.0/8"``` and ```"239.0.0.0/8"``` is also can return corresponding mac address.
* ```"lookup_ip_address()"```: Lookup corresponding IP address. Parameter is a MAC address. Example: ```lookup_ip_address(1:2:3:4:5:6)``` . If is not found. return ```"0.0.0.0"```.
* ```"random_ip_address()"```: Generating an IP address randomly. Not generate: 0.0.0.0, broadcast address, multicast address, experimental address, private address, loopback address and 0.0.0.0/8.
* ```"random_mac_address()"```: Generating a MAC address randomly. Not generate: multicast address and broadcast address.
* ```"random()"```: Generate a number. No parameter which mean random number range is 0-4294967295. Parameter can be a range, ```random(1-100)``` generate a number between 1-100. Reserved word: ```Well-known``` and ```Official``` which mean random number range is 0-1023. ```Unofficial``` and ```Registered``` is 1024-49151. ```Multiple use```, ```Dynamic```, ```Private``` and ```Ephemeral``` is 49152-65535. ```u_int8_t```is 0-255. ```u_int16_t``` is 0-65535. ```u_int32_t``` is 0-4294967295(Default).
* ```"multicast_address()"```: Return multicast address of specify protocol. ```"RIPv2"``` return ```"224.0.0.9"```. ```"SSDP"``` return ```"239.255.255.250"```.
* ```"port()"```: Get port number by protocol name. ```"HTTP"``` return ```80```, ```"HTTPS"``` return ```443```, ```"DNS"``` return ```53```, ```"SSH"``` return ```22```, ```"Telnet"``` return ```23```, ```"RIP"``` return ```520```, ```"Wake-On-LAN"```(or ```"WOL"```) return ```9```, ```"SSDP"``` return ```1900```, ```"DHCP-server"``` return ```67```, ```"DHCP-client"``` return ```68```.

##Socket option
* ```"_comment"```(string, optional)：註解。
* ```"Socket-type"```(string, required)：可用```"Data-link"```、```"Network"```、```"Transport"```。
* ```""Option""```(object, required)：整個socket的參數。
* ```"Sequence"```(array, required)：個別封包。

</br>

* ```"_comment"```(string, optional): Comment.
* ```"Socket-type"```(string, required): ```"Data-link"```, ```"Network"``` and ```"Transport"``` are available.
* ```""Option""```(object, required): Whole socket option.
* ```"Sequence"```(array, required): Each packet.

###Data-link socket option
* ```"Device"```(string, optional, default: 略過loopback後的第一個有IP地址的device)：要送出封包的device，最好是手動設定。
* ```"Amount"```(integer: 4 bytes, optional, default: 1)：送出輪數(次數)。
* ```"Infinite loop"```(boolean, optional, default: "disable")：是否需要無窮迴圈，如果被設定則```"Amount"```無效果。
* ```"Interval"```(integer: 4 bytes, optional, default: 0)：每輪間隔，單位微秒(microsecond)，預設0表示無間隔。

</br>

* ```"Device"```(string, optional, default: Skip loopback, the first device with IP address): Device that frame send. Manually fill is better.
* ```"Amount"```(integer: 4 bytes, optional, default: 1): Rounds.
* ```"Infinite loop"```(boolean, optional, default: "disable"): Infinite loop or not, if set, ```"Amount"``` is not effective.
* ```"Interval"```(integer: 4 bytes, optional, default: 0): Inerval of each round. Microsecond, default 0 wich mean no interval.

###Network socket option
* ```"Device"```(string, optional, default: 讓Route table選擇device)：要送出封包的device。
* ```"Amount"```(integer: 4 bytes, optional, default: 1)：送出輪數(次數)。
* ```"Infinite loop"```(boolean, optional, default: "disable")：是否需要無窮迴圈，如果被設定則```"Amount"```無效果。
* ```"Interval"```(integer: 4 bytes, optional, default: 0)：每輪間隔，單位微秒(microsecond)，預設0表示無間隔。

</br>

* ```"Device"```(string, optional, default: Route table choose device): Device that packet send.
* ```"Amount"```(integer: 4 bytes, optional, default: 1): Rounds.
* ```"Infinite loop"```(boolean, optional, default: "disable"): Infinite loop or not, if set, ```"Amount"``` is not effective.
* ```"Interval"```(integer: 4 bytes, optional, default: 0): Inerval of each round. Microsecond, default 0 wich mean no interval.

###Transport socket option
* ```"Device"```(string, optional, default: 讓Route table選擇device)：要送出封包的device。
* ```"Amount"```(integer: 4 bytes, optional, default: 1)：送出輪數(次數)。
* ```"Infinite loop"```(boolean, optional, default: "disable")：是否需要無窮迴圈，如果被設定則```"Amount"```無效果。
* ```"Interval"```(integer: 4 bytes, optional, default: 0)：每輪間隔，單位微秒(microsecond)，預設0表示無間隔。
* ```"Destination IP Address"```(address, required)。
* ```"Protocol"```(string, required)：傳輸層協定，只能用```"IPPROTO_ICMP"```、```"IPPROTO_TCP"```、```"IPPROTO_UDP"```。

</br>

* ```"Device"```(string, optional, default: Route table choose device): Device that packet send.
* ```"Amount"```(integer: 4 bytes, optional, default: 1): Rounds.
* ```"Infinite loop"```(boolean, optional, default: "disable"): Infinite loop or not, if set, ```"Amount"``` is not effective.
* ```"Interval"```(integer: 4 bytes, optional, default: 0): Inerval of each round. Microsecond, default 0 wich mean no interval.
* ```"Destination IP Address"```(address, required).
* ```"Protocol"```(string, required): Transport layer protocol, ```"IPPROTO_ICMP"```, ```"IPPROTO_TCP"``` or ```"IPPROTO_UDP"``` only.

###Application socket option
* ```"Device"```(string, optional, default: 讓Route table選擇device)：要送出封包的device。
* ```"Amount"```(integer: 4 bytes, optional, default: 1)：送出輪數(次數)。
* ```"Infinite loop"```(boolean, optional, default: "disable")：是否需要無窮迴圈，如果被設定則```"Amount"```無效果。
* ```"Interval"```(integer: 4 bytes, optional, default: 0)：每輪間隔，單位微秒(microsecond)，預設0表示無間隔。
* ```"Type"```(string, required)：傳輸層類型，只能是```"SOCK_STREAM"```或```"SOCK_DGRAM"```，```"SOCK_STREAM"```通常使用TCP，```"SOCK_DGRAM"```通常使用UDP。
* ```"Send Timeout"```(integer: 4 bytes, optional, default: 0)：送出超時時間，預設表示會阻塞著直到送出封包，單位微秒(microsecond)。
* ```"Receive Timeout"```(integer: 4 bytes, optional, default: 0)：接收超時時間，預設表示會阻塞著直到接收封包，單位微秒(microsecond)。
* ```"Role"```(string, required)：只能是```"Server"```或```"Client"```。

</br>

* ```"Device"```(string, optional, default: Route table choose device): Device that packet send.
* ```"Amount"```(integer: 4 bytes, optional, default: 1): Rounds.
* ```"Infinite loop"```(boolean, optional, default: "disable"): Infinite loop or not, if set, ```"Amount"``` is not effective.
* ```"Interval"```(integer: 4 bytes, optional, default: 0): Inerval of each round. Microsecond, default 0 wich mean no interval.
* ```"Type"```(string, required): Transport layer type, ```"SOCK_STREAM"``` or ```"SOCK_DGRAM"``` only. ```"SOCK_STREAM"``` usually is TCP, ```"SOCK_DGRAM"``` usually is UDP.
* ```"Send Timeout"```(integer: 4 bytes, optional, default: 0): Send timeout, default 0 which mean block until send. Microsecond.
* ```"Receive Timeout"```(integer: 4 bytes, optional, default: 0): Receive timeout, default 0 which mean block until receive. Microsecond.
* ```"Role"```(string, required):```"Server"``` or ```"Client"``` only.

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

</br>

If ```"SOCK_DGRAM"```:

* ```"Muliticast Group"```(array, optional): Each is string, must be multicast address(not check). ```"multicast address()"``` is available. If ```"Device"``` set, ```"Multicast Group"``` will not effective.


If ```"SOCK_STREAM"```:

* ```"Asynchronous"```(boolean, optional, default: "disable"): Processing client connection asynchronous or not, default synchronous.
* ```"Max Connection"```(integer: 2 bytes, optional, default: 1024): Maximum client connection.
* ```"Security"```(boolean, optional, default: "disable"): Enable security socket or not.

####Application role condition(extract option)
如果是```"Server"```：

* ```"Source Port"```(interger 2 bytes, required)：接收特定Port的封包。

> 如果```"Type"```是```"SOCK_DGRAM"```，應先使用```"Receive Packet"```再使用```"Send Packet"```，而```"Send Packet"```的目的IP地址會是```"Receive Packet"```最後收到的IP地址。

如果是```"Server"```且```"Type"```是```"SOCK_STREAM"```且```"Security"```是```"enable"```：

* ```"Method"```(string, optional, depends: "Type")：加密方法，當```"Type"```是```"SOCK_STREAM"```，default: ```"SSLv23"```，只能使用```"SSLv2"```、```"SSLv3"```、```"SSLv23"```、```"TLSv1.0"```、```"TLSv1.1"```、```"TLSv1.2"```，其中```"SSLv23"```表示盡量使用SSL/TLS可用的最高版本。
* ```"Certificate"```(string, requried)：憑證檔案路徑，必須是PEM格式。
* ```"Private key"```(string, requried)：私鑰檔案路徑，必須是PEM格式。

如果是```"Client"```：

* ```"Destination IP Address"```(address, required)：送至特定IP地址。
* ```"Destination Port"```(interger 2 bytes, required)：送至特定Port。

> 如果```"Type"```是```"SOCK_DGRAM"```，應先使用```"Send Packet"```再使用```"Receive Packet"```，而```"Receive Packet"```的來源Port會是```"Send Packet"```最後收到的Port。

如果是```"Client"```且```"Type"```是```"SOCK_STREAM"```且```"Security"```是```"enable"```：

* ```"Method"```(string, optional, depends: "Type")：加密方法，當```"Type"```是```"SOCK_STREAM"```，default：```"SSLv23"```，只能使用```"SSLv2"```、```"SSLv3"```、```"SSLv23"```、```"TLSv1.0"```、```"TLSv1.1"```、```"TLSv1.2"```，其中```"SSLv23"```表示盡量使用SSL/TLS可用的最高版本。
* ```"Certificate"```(string, optional, default: 自動產生)：憑證檔案路徑，必須是PEM格式。
* ```"Private key"```(string, optional, default: 自動產生)：私鑰檔案路徑，必須是PEM格式。
* ```"Certificate Information"```(boolean, optional, default: "disable")：是否要顯示Server的憑證資訊。

<!--；當```"Type"```是```"SOCK_DGRAM"```，default: ```"DTLS"```，只能使用```"DTLS"```、```"DTLS1.0"```、```"DTLS1.2"```，其中```"DTLS"```表示盡量使用DTLS可用的最高版本-->

</br>

If ```"Server"```:

* ```"Source Port"```(interger 2 bytes, required): Receive packet from specify port number.

> If ```"Type"``` is ```"SOCK_DGRAM"```. ```"Receive Packet"``` should be first call and then ```"Send Packet"```. Destination IP address of ```"Send Packet"``` is the final receive from ```"Receive Packet"```.

If ```"Server"``` and ```"Type"``` is ```"SOCK_STREAM"``` and ```"Security"``` is ```"enable"```:

* ```"Method"```(string, optional, depends: "Type"): Cryptography. When ```"Type"``` is ```"SOCK_STREAM"```, default: ```"SSLv23"```. ```"SSLv2"```, ```"SSLv3"```, ```"SSLv23"```, ```"TLSv1.0"```, ```"TLSv1.1"``` and ```"TLSv1.2"``` only. ```"SSLv23"``` means use SSL/TLS version as highest as possible.
* ```"Certificate"```(string, required): Ceritficate file path, PEM format only.
* ```"Private key"```(string, requried)：Private key file path, PEM format only.

If ```"Client"```:

* ```"Destination IP Address"```(address, required): Send to specify IP address.
* ```"Destination Port"```(interger 2 bytes, required)：Send to specify port number.

> If ```"Type"``` is ```"SOCK_DGRAM"```. ```"Send Packet"``` should be first call and then ```"Receive Packet"```. Source port of ```"Receive Packet"``` is the fianl send from ```"Send Packet"```.

If ```"Client"``` and ```"Type"``` is ```"SOCK_STREAM"``` and ```"Security"``` is ```"enable"```:

* ```"Method"```(string, optional, depends: "Type"): Cryptography. When ```"Type"``` is ```"SOCK_STREAM"```, default: ```"SSLv23"```. ```"SSLv2"```, ```"SSLv3"```, ```"SSLv23"```, ```"TLSv1.0"```, ```"TLSv1.1"``` and ```"TLSv1.2"``` only. ```"SSLv23"``` means use SSL/TLS version as highest as possible.
* ```"Certificate"```(string, optional, default: auto generate): Ceritficate file path, PEM format only.
* ```"Private key"```(string, optional, default: auto generate): Private key file path, PEM format only.
* ```"Certificate Information"```(boolean, optional, default: "disable"): Show server cerificate information or not.

###Send packet comment option
* ```"Amount"```(integer: 4 bytes, optional, default: 1)：送出數量。
* ```"Infinite loop"```(boolean, optional, default: "disable")：是否需要無窮迴圈，如果被設定則```"Amount"```無效果。
* ```"Interval"```(integer: 4 bytes, optional, default: 0)：每個封包間隔，單位微秒(microsecond)，預設0表示無間隔。
* ```"Dump send packet"```(boolean, optional, default: "disable")：送出封包後，是否要將封包解析出來。

</br>

* ```"Amount"```(integer: 4 bytes, optional, default: 1): Send amount.
* ```"Infinite loop"```(boolean, optional, default: "disable"): Infinite loop or not, if set, ```"Amount"``` is not effective.
* ```"Interval"```(integer: 4 bytes, optional, default: 0): Inerval of each packet. Microsecond, default 0 wich mean no interval.
* ```"Dump send packet"```(boolean, optional, default: "disable"): After sending, dump send packet or not.


###Receive packet comment option

> 無，除了```"Application"```以外，暫無接收封包功能。

</br>

> Empty. Not support receive packet for now, except ```"Application"```.

####Application send packet(extract option)
* ```"Send Timeout"```(integer: 4 bytes, optional, default: 0)：送出超時時間，預設表示會阻塞著直到送出封包，單位微秒(microsecond)。
* ```"Send Length"```(integer: 2 bytes, optional, default: 0)：送出封包大小，0表示自動計算。
* ```"Interactive"```(boolean, optional, default: "disable")：封包內容(Message)是否手動輸入，該選項與```"Input from file"```互斥。
* ```"Input from file"```(string, optional, default: NULL)：從檔案讀入封包內容(Message)送出，該選項與```"Interactive"```互斥。

> Interactive(互動模式)是指可以在程式執行階段時，讓使用者用輸入的方式決定送出封包，輸入結束使用EOF訊號表示結束（Windows：Ctrl+Z，*nux：Ctrl+D)；有些特殊字元輸入方式與C語言相同，可用：```'\a'```、```'\b'```、```'\f'```、```'\n'```、```'\r'```、```'\t'```、```'\v'```，如果輸入```'\'```即是反斜線，按下Enter鍵並不會加入換行字元。

</br>

* ```"Send Timeout"```(integer: 4 bytes, optional, default: 0): Send timeout, default 0 which mean block until send. Microsecond.
* ```"Send Length"```(integer: 2 bytes, optional, default: 0): Length of send packet. 0 means auto calculate.
* ```"Interactive"```(boolean, optional, default: "disable"): Packet message input manually. Mutual exclusion to ```"Input from file"```.

> Interactive mode means input from keyboard when runtime, send EOF to terminate(Windows：Ctrl+Z, *nux：Ctrl+D). ```'\a'```, ```'\b'```, ```'\f'```, ```'\n'```, ```'\r'```, ```'\t'``` and ```'\v'``` are available. ```'\'``` is ```'\'```. Enter key won't append newline character.

####Application receive packet(extract option)
* ```"Amount"```(integer: 4 bytes, optional, default: 1)：送出數量。
* ```"Infinite loop"```(boolean, optional, default: "disable")：是否需要無窮迴圈，如果被設定則```"Amount"```無效果。
* ```"Interval"```(integer: 4 bytes, optional, default: 0)：每個封包間隔，單位微秒(microsecond)，預設0表示無間隔。
* ```"Dump receive packet"```(boolean, optional, default: "disable")：收到封包後，是否要將封包解析出來。
* ```"Receive Timeout"```(integer: 4 bytes, optional, default: 0)：接收超時時間，預設表示會阻塞著直到接收封包，單位微秒(microsecond)。
* ```"Read until Timeout"```(boolean, optional, default: "disable")：讀取封包，如果Timeout就結束讀取，會忽略```""Infinite loop"```的設定。
* ```"Output to file"```(string, optional, default: NULL)：將接收到的封包內容(Message)輸出到檔案。

</br>

* ```"Amount"```(integer: 4 bytes, optional, default: 1): Send amount.
* ```"Infinite loop"```(boolean, optional, default: "disable"): Infinite loop or not, if set, ```"Amount"``` is not effective.
* ```"Interval"```(integer: 4 bytes, optional, default: 0): Inerval of each packet. Microsecond, default 0 wich mean no interval.
* ```"Dump receive packet"```(boolean, optional, default: "disable"): After receiving, dump received packet or not.
* ```"Receive Timeout"```(integer: 4 bytes, optional, default: 0): Receive timeout, default 0 which mean block until receive. Microsecond.
* ```"Read until Timeout"```(boolean, optional, default: "disable"): Keep receiving packet until timeout. Ignore ```""Infinite loop"```.
* ```"Output to file"```(string, optional, default: NULL): Output received message to file.

##Procotol headers
* [```"Ethernet"```](Socket/Ethernet.md)
* [```"ARP"```](Socket/ARP.md)
* [```"RARP"```](Socket/ARP.md)
* [```"Wake-On-LAN"```](Socket/WOL.md)
* [```"IPv4"```](Socket/IPv4.md)
* [```"IPv4 Options"```](Socket/IPv4.md)
* [```"UDP"```](Socket/UDP.md)
* [```"TCP"```](Socket/TCP.md)
* [```"TCP Options"```](Socket/TCP.md)
* [```"ICMPv4 Echo/Request"```](Socket/ICMPv4.md)
* [```"ICMPv4 Time Exceeded"```](Socket/ICMPv4.md)
* [```"ICMPv4 Destination Unreachable"```](Socket/ICMPv4.md)
* [```"ICMPv4 Redirect"```](Socket/ICMPv4.md)
* [```"RIPv1/RIPv2"```](Socket/RIP.md)
* [```"SSDP"```](Socket/Message.md)
* [```"HTTP"```](Socket/Message.md)
* [```"DHCPv4"```](Socket/DHCPv4.md)
* [```"DHCPv4 Options"```](Socket/DHCPv4.md)
* [```"SSL/TLS"```](Socket-Configuration.md)
* [```"Other"```](Socket/Other.md)