#arping

arping 模型。

</br>

arping model.

##Option

* ```"Amount"```(integer: 4 bytes, optional, default: 1)：送出輪數(次數)。
* ```"Interval"```(integer: 4 bytes, optional, default: 0)：每輪間隔，單位豪秒(millisecond)。
* ```"Infinite loop"```(boolean, optional, default: "disable")：是否需要無窮迴圈，如果被設定則```"Amount"```無效果。
* ```"Dump send packet"```(boolean, optional, default: "disable")：送出封包後，是否要將封包解析出來。
* ```"Dump receive packet"```(boolean, optional, default: "disable")：收到封包後，是否要將封包解析出來。
* ```"Receive Timeout"```(integer: 4 bytes, optional, default: 1)：接收超時時間，單位豪秒(millisecond)。
* ```Filter"```(string, optional, default: "arp host "Target" and arp[6:2] == 0x0002")：預設只接收```"Target"```的ARP reply封包，例如：```"Target"```是```"192.168.1.100"```，過濾器為```"arp host 192.168.1.100 and arp[6:2] == 0x0002"```。
* ```"Device"```(string, optional, default: 略過loopback後的第一個有IP地址的device)：要送出封包的device，最好是手動設定。

</br>

* ```"Amount"```(integer: 4 bytes, optional, default: 1): Rounds.
* ```"Interval"```(integer: 4 bytes, optional, default: 0): Inerval of each round. Millisecond.
* ```"Infinite loop"```(boolean, optional, default: "disable"): Infinite loop or not, if set, ```"Amount"``` is not effective.
* ```"Dump send packet"```(boolean, optional, default: "disable"): After sending, dump send packet or not.
* ```"Dump receive packet"```(boolean, optional, default: "disable"): After receiving, dump received packet or not.
* ```"Receive Timeout"```(integer: 4 bytes, optional, default: 1): Receive timeout. Millisecond.
* ```Filter"```(string, optional, default: "arp host "Target" and arp[6:2] == 0x0002"): Default is receive ARP reply frame of ```"Target"```. Example: Let ```"Target"``` is ```"192.168.1.100"```, then filter expression is ```"arp host 192.168.1.100 and arp[6:2] == 0x0002"```.
* ```"Device"```(string, optional, default: Skip loopback, the first device with IP address): Device that frame send. Manually fill is better.

##arping model

* ```"Target"```(address, required)：可用```"lookup_ip_address()"```來查詢IP地址。

</br>

* ```"Target"```(address, required): ```"lookup_ip_address()"``` is available.

##Example

```
{
    "Option": {
        "Model": "arping",
        "_comment": "arping to 192.168.1.1",
        "Device": "en0",
        "Amount": 4,
        "Interval": 1000000,
        "Receive Timeout": 1000
    },

    "Model": {
        "Target": "192.168.1.1"
    }
}
```