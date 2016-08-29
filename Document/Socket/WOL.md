#Wake-On-LAN

Wake-On-LAN表頭。

</br>

Wake-On-LAN header.

##Wake-On-LAN header
* ```"Sync Stream"```(other 6 bytes, optional, default: "ff:ff:ff:ff:ff:ff")：以MAC Address方式表示。
* ```"MAC Address"```(address, required)。
* ```"Password"```(address, optional, default: "00:00:00:00:00:00")。

> Wake-On-LAN能夠用在Frame(Layer 2, over Ethernet)或是Message(Layer 5 over UDP)。

</br>

* ```"Sync Stream"```(other 6 bytes, optional, default: "ff:ff:ff:ff:ff:ff"): MAC Address format.
* ```"MAC Address"```(address, required).
* ```"Password"```(address, optional, default: "00:00:00:00:00:00").

> Wake-On-LAN use frame(Layer 2, over Ethernet) or message(Layer 5 over UDP).

###Wake-On-LAN Example

```
{
    "Wake-On-LAN": {
        "Sync Stream": "ff:ff:ff:ff:ff:ff",
        "MAC Address": "lookup_mac_address(192.168.1.100)",
        "Password": "1:2:3:4:5:6"
    }
}
```