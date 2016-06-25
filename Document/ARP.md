#ARP and RARP

ARP和RARP表頭。

</br>

ARP and RARP header.

##ARP/RARP header
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

</br>

* ```"Hardware Type"```(integer 2 bytes, optional, default: 1).
* ```"Protocol Type"```(integer 2 bytes, optional, default: "0x0800").
* ```"Hardware Address Length"```(integer 1 byte, optional, default: 6).
* ```"Protocol Address Length"```(integer 1 byte, optional, default: 4).
* ```"Operation"```(integer 2 bytes, required): ```"ARPOP_REPLY"```, ```"ARPOP_REQUEST"```, ```"ARPOP_REVREPLY"```, ```"ARPOP_REVREQUEST"``` are available.
* ```"Sender Hardware Address"```(address, required): ```"random_mac_address()"``` and ```"lookup_mac_address()"``` are available.
* ```"Sender Protocol Address"```(address, required): ```"random_ip_address()"``` and ```"lookup_ip_address()"``` are available.
* ```"Target Hardware Address"```(address, required): ```"random_mac_address()"``` and ```"lookup_mac_address()"``` are available.
* ```"Target Protocol Address"```(address, required): ```"random_ip_address()"``` and ```"lookup_ip_address()"``` are available.

> ARP/RARP supported Ethernet ARP/RARP only.

##ARP Example

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