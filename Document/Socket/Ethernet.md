#Ethernet

以太表頭。

</br>

Ethernet header.

##Ethernet header
* ```"Destination MAC Address"```(address, required)：可用```"random_mac_address()"```隨機產生一個地址，也可以使用```"lookup_mac_address()"```來查詢MAC地址。
* ```"Source MAC Address"```(address, optional, default: "myself")：可用```"random_mac_address()"```隨機產生一個地址，也可以使用```"lookup_mac_address()"```來查詢MAC地址。
* ```"Type"```(integer 2 bytes, required)：另外可用```"ETHERTYPE_IP"```、```"ETHERTYPE_ARP"```、```"ETHERTYPE_REVARP"```、```"ETHERTYPE_WOL"```。

</br>

* ```"Destination MAC Address"```(address, required): ```"random_mac_address()"``` and ```"lookup_mac_address()"``` are available.
* ```"Source MAC Address"```(address, optional, default: "myself"): ```"random_mac_address()"``` and ```"lookup_mac_address()"``` are available.
* ```"Type"```(integer 2 bytes, required): ```"ETHERTYPE_IP"```, ```"ETHERTYPE_ARP"```, ```"ETHERTYPE_REVARP"``` and ```"ETHERTYPE_WOL"``` are available.

###Ethernet Example

```
{
    "Ethernet": {
        "Destination MAC Address": "lookup_mac_address(192.168.1.1)",
        "Source MAC Address": "myself",
        "Type": "ETHERTYPE_ARP"
    }
}
```