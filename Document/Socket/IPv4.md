#IPv4 and IPv4 options

IPv4和IPv4 options表頭。

</br>

IPv4 and IPv4 options header.

##IP(IPv4) header
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

</br>

* ```"Type of Service"```(binary 8 bits, optional, default: "00000000"): Length must be 8.
* ```"Total Length"```(integer 2 bytes, optional, default: "auto"): 0 means auto calculate.
* ```"Identification"```(integer 2 bytes, optional, default: "random(u\_int16\_t)"): ```"random()"``` is available.
* ```"Flags"```(others 3 bits, optional, default: 0): ```"IP_RF"```, ```"IP_DF"``` and ```"IP_MF"``` only. "|" is available, example: ```"IP_RF | IP_DF"```.
* ```"Fragment Offset"```(integer 2 bytes, optional, default: 0).
* ```"Time to Live"```(integer 1 byte, optional, default: 64).
* ```"Protocol"```(integer 1 byte, required): ```"IPPROTO_ICMP"```, ```"IPPROTO_UDP"``` and ```"IPPROTO_TCP"``` are available.
* ```"Header Checksum"```(integer 2 bytes, optional, default: "auto"): ```"auto"``` and 0 means auto calculate.
* ```"Source IP Address"```(address, optional, default: "myself"): ```"random_ip_address()"```, ```"lookup_ip_address()"``` and ```"multicast_address()"``` are available. specify a hostname is also available.
* ```"Destination IP Address"```(address, required): ```"random_ip_address()"```, ```"lookup_ip_address()"``` and ```"multicast_address()"``` are available. specify a hostname is also available.

##IP(IPv4) Example

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

##IPv4 Options
* ```"Type"```(integer 1 byte, required)：可使用```"IPOPT_EOL"```、```"IPOPT_RR"```。

> IPv4 Options必須為4的倍數。

</br>

* ```"Type"```(integer 1 byte, required): ```"IPOPT_EOL"``` and ```"IPOPT_RR"``` are available.

> IPv4 Options must be times of 4.

###IPv4 Option IPOPT_RR(Record Route, 7)
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

</br>

* ```"Length"```(integer 1 byte, optional, default: 39): Default: 39-3=36/4=9, 9 routes is maximum value of record route. The value must be times of 4 after subtract 3.
* ```"Pointer"```(integer 1 byte, optional, default: 4).
* ```"Route1"```(address, optional, default: "0.0.0.0").
* ```"Route2"```(address, optional, default: "0.0.0.0").
* ```"Route3"```(address, optional, default: "0.0.0.0").
* ```"Route4"```(address, optional, default: "0.0.0.0").
* ```"Route5"```(address, optional, default: "0.0.0.0").
* ```"Route6"```(address, optional, default: "0.0.0.0").
* ```"Route7"```(address, optional, default: "0.0.0.0").
* ```"Route8"```(address, optional, default: "0.0.0.0").
* ```"Route9"```(address, optional, default: "0.0.0.0").

###IPv4 Option IPOPT_EOL(End of Line, 0)

> 無。

</br>

> None.

###IPv4 Options Example

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