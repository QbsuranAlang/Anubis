#RIP

RIP表頭。

</br>

RIP header.

##RIP
* ```"Command"```(integer 1 byte, required)：另外可用```"RIPCMD_REQUEST"```、```"RIPCMD_RESPONSE"```、```"RIPCMD_TRACEON"```、```"RIPCMD_TRACEOFF"```、```"RIPCMD_POLL"```以及```"RIPCMD_POLLENTRY"```。
* ```"Version"```(integer 1 byte, required)：另外可用```"RIPVER_0"```、```"RIPVER_1"```以及```"RIPVER_2"```。
* ```"Routing Domain"```(integer 2 bytes, optional, default: 0)：```"RIPVER_2"```使用的，在```"RIPVER_1"```應該為0。
* ```"Route Table Entry"```(array, required)：每項路由訊息陣列，可以簡寫成```"RTE"```。

</br>

* ```"Command"```(integer 1 byte, required): ```"RIPCMD_REQUEST"```, ```"RIPCMD_RESPONSE"```, ```"RIPCMD_TRACEON"```, ```"RIPCMD_TRACEOFF"```, ```"RIPCMD_POLL"``` and ```"RIPCMD_POLLENTRY"``` are available.
* ```"Version"```(integer 1 byte, required): ```"RIPVER_0"```, ```"RIPVER_1"``` and ```"RIPVER_2"``` are available.
* ```"Routing Domain"```(integer 2 bytes, optional, default: 0): Use by ```"RIPVER_2"```. Should be 0 when use ```"RIPVER_1"```.
* ```"Route Table Entry"```(array, required)：Each route information array. It can be shortened to ```"RTE"```.

###RIP Route Table Entry
* ```"Address Family"```(integer 2 bytes, required)：另外可用```AF_INET```。
* ```"Route Tag"```(integer 2 bytes, optional, default: 0)：```"RIPVER_2"```使用的，在```"RIPVER_1"```應該為0。
* ```"IP Address"```(address, required)：可用```"random_ip_address()"```隨機產生一個地址，也可以用```"lookup_ip_address()"```來查詢IP地址，也可以使用Hostname表示，還可以用```"multicast_address()"```來取得特定協定的群播地址。
* ```"Netmask"```(address, required)：可用```"random_ip_address()"```隨機產生一個地址，也可以用```"lookup_ip_address()"```來查詢IP地址，也可以使用Hostname表示，還可以用```"multicast_address()"```來取得特定協定的群播地址。
* ```"Next hop"```(address, optional, default: "0.0.0.0")：```"RIPVER_2"```使用的，在```"RIPVER_1"```應該為0.0.0.0；可用```"random_ip_address()"```隨機產生一個地址，也可以用```"lookup_ip_address()"```來查詢IP地址，也可以使用Hostname表示，還可以用```"multicast_address()"```來取得特定協定的群播地址。
* ```"Metric"```：(integer 4 bytes, required)。

</br>

* ```"Address Family"```(integer 2 bytes, required): ```AF_INET``` is available.
* ```"Route Tag"```(integer 2 bytes, optional, default: 0): Use by ```"RIPVER_2"```. Should be 0 when use ```"RIPVER_1"```.
* ```"IP Address"```(address, required): ```"random_ip_address()"```, ```"lookup_ip_address()"``` and ```"multicast_address()"``` are available. specify a hostname is also available.
* ```"Netmask"```(address, required): ```"random_ip_address()"```, ```"lookup_ip_address()"``` and ```"multicast_address()"``` are available.
* ```"Next hop"```(address, optional, default: "0.0.0.0"):  Use by ```"RIPVER_2"```. Should be 0.0.0.0 when use ```"RIPVER_1"```. ```"random_ip_address()"```, ```"lookup_ip_address()"``` and ```"multicast_address()"``` are available. specify a hostname is also available.
* ```"Metric"```：(integer 4 bytes, required).

###RIP Example

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