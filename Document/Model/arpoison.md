#arpoison

arpoison模型。

</br>

arpoison model.

##Option

* ```"Amount"```(integer: 4 bytes, optional, default: 0)：送出輪數(次數)。
* ```"Dump send packet"```(boolean, optional, default: "disable")：送出封包後，是否要將封包解析出來。
* ```"Device"```(string, optional, default: 略過loopback後的第一個有IP地址的device)：要送出封包的device，最好是手動設定。
* ```"Interval"```(integer: 4 bytes, optional, default: 3000000)：每輪間隔，單位豪秒(millisecond)。
* ```"Infinite loop"```(boolean, optional, default: "enable")：是否需要無窮迴圈，如果被設定則```"Amount"```無效果。

</br>

* ```"Amount"```(integer: 4 bytes, optional, default: 0): Rounds.
* ```"Dump send packet"```(boolean, optional, default: "disable"): After sending, dump send packet or not.
* ```"Device"```(string, optional, default: Skip loopback, the first device with IP address): Device that frame send. Manually fill is better.
* ```"Interval"```(integer: 4 bytes, optional, default: 3000000): Inerval of each round. Millisecond.
* ```"Infinite loop"```(boolean, optional, default: "enable"): Infinite loop or not, if set, ```"Amount"``` is not effective.

##arpoison model

* ```"Hosts"```(array, required)：目標主機，全部必須是字串，另外可以使用slash或一個範圍表示；例如：```"192.168.1.0/25"```、```"192.168.1.100-192.168.1.150"```或```"192.168.1.200"```。
* ```"Reversed"```(address, required)：另一個主機，例如預設路由，可以填入```"Default-route"```代替。
* ```"Interval"```(integer: 4 bytes, optional, default: 10000)：每個ARP封包間隔時間。
* ```"White"```(array, optional)：白名單，全部必須是字串，另外可以使用slash或一個範圍表示，可以用```"Myself"```略過自己。
* ```"Operation"```(integer 2 bytes, optional, default: "ARPOP_REPLY")：另外可用```"ARPOP_REPLY"```和```"ARPOP_REQUEST"```。
* ```"Sender Hardware Address"```(address, optional, default: "Myself")：可用```"random_mac_address()"```隨機產生一個地址，也可以使用```"lookup_mac_address()"```來查詢MAC地址。

</br>

* ```"Hosts"```(array, required): Target hosts, string only. CIRD or IP range are available. Example: ```"192.168.1.0/25"```, ```"192.168.1.100-192.168.1.150"``` or ```"192.168.1.200"```.
* ```"Reversed"```(address, required): Another target. For example: default gateway, ```"Default-route"``` to symbol it.
* ```"Interval"```(integer: 4 bytes, optional, default: 10000): Interval of each ARP frame.
* ```"White"```(array, optional): White list. String only. CIRD or IP range are available. ```"Myself"``` is available, too.
* ```"Operation"```(integer 2 bytes, optional, default: "ARPOP_REPLY"): ```"ARPOP_REPLY"``` and ```"ARPOP_REQUEST"``` are available.
* ```"Sender Hardware Address"```(address, optional, default: "Myself"): ```"random_mac_address()"``` and ```"lookup_mac_address()"``` are available.

##Example

```
{
    "Option": {
        "Model": "arpoison",
        "_comment": "arpoison to hosts and reversed to router",
        "Device": "en0"
    },

    "Model": {
        "Hosts": ["192.168.1.0/24"],
        "Reversed": "Default-route",
        "White": ["Myself"],
        "Operation": "ARPOP_REQUEST"
    }
}
```


