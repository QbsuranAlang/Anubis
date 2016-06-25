#DHCPv4 and DHCPv4 options

DHCPv4和DHCPv4 options表頭。

</br>

DHCPv4 and DHCPv4 options header.

##DHCPv4 header
* ```"Operation Code"```(integer: 1 byte, required)：另外可用```"DHCP_REQUEST"```、```"DHCP_REPLY"```。
* ```"Hardware Address Type"```(integer: 1 byte, optional, default: "0x1")：預設0x1表示乙太網路。
* ```"Hardware Address Length"```(integer: 1 byte, optional, default: 6)。
* ```"Hops"```(integer: 1 byte, optional, default: 0)：proxy servers使用。
* ```"Transaction ID"```(integer: 4 bytes, optional, default: "random(u\_int16\_t)")：可以用```"random()"```取得亂數。
* ```"Seconds"```(integer: 2 bytes, optinoal, default: 0)：目前section所花的時間。
* ```"Broadcast Flags"```(boolean, optional, default: "disable")：```"enable"```是Unicast，BOOTP不使用。
* ```"Client IP Address"```(address, optional, default: "0.0.0.0")。
* ```"Your IP Address"```(address, optional, default: "0.0.0.0")：Client IP address。
* ```"Server IP Address"```(address, optional, default: "0.0.0.0")：Next server IP address。
* ```"Gateway IP Address"```(address, optional, default: "0.0.0.0")：Relay agent IP address。
* ```"Client MAC Address"```(address, optional, default: "myself")。
* ```"Server Hostname"```(string, optional, default: NULL)。
* ```"Boot File Name"```(string, optional, default: NULL)。

</br>

* ```"Operation Code"```(integer: 1 byte, required): ```"DHCP_REQUEST"``` and ```"DHCP_REPLY"``` are available.
* ```"Hardware Address Type"```(integer: 1 byte, optional, default: "0x1"): Default 0x1 means ethernet.
* ```"Hardware Address Length"```(integer: 1 byte, optional, default: 6).
* ```"Hops"```(integer: 1 byte, optional, default: 0)：proxy servers使用.
* ```"Transaction ID"```(integer: 4 bytes, optional, default: "random(u\_int16\_t)"): ```"random()"``` is available.
* ```"Seconds"```(integer: 2 bytes, optinoal, default: 0): Current section spend time.
* ```"Broadcast Flags"```(boolean, optional, default: "disable"): ```"enable"``` is Unicast, BOOTP is disabled.
* ```"Client IP Address"```(address, optional, default: "0.0.0.0").
* ```"Your IP Address"```(address, optional, default: "0.0.0.0"): Client IP address.
* ```"Server IP Address"```(address, optional, default: "0.0.0.0"): Next server IP address.
* ```"Gateway IP Address"```(address, optional, default: "0.0.0.0"): Relay agent IP address.
* ```"Client MAC Address"```(address, optional, default: "myself").
* ```"Server Hostname"```(string, optional, default: NULL).
* ```"Boot File Name"```(string, optional, default: NULL).

###DHCPv4 Example

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

> DHCP封包（包含Option）最小需要300 bytes，所以填寫UDP和IP長度欄位時需要注意（RFC1542），或者直接使用```"auto"```。

</br>

> DHCP message(include option) minimum size is 300 byte. Fill UDP and IP length field must be attention (RFC1542). Or just use ```"auto"``` to replace.

##DHCPv4 Options
* ```"Type"```(integer: 1 byte, required)：可使用```"DHCP_MESSAGETYPE"```、```"DHCP_CLIENTID"```、```"DHCP_REQUESTED_IP_ADDRESS"```、```"DHCP_PARAMREQUEST"```、```"DHCP_PAD"```、```"DHCP_SERVER"```、```"DHCP_LEASETIME"```、```"DHCP_SUBNETMASK"```、```"DHCP_ROUTER"```、```"DHCP_DNS_SERVER"```、```"DHCP_NTP_SERVER"```、```"DHCP_RENEWTIME"```、```"DHCP_REBINDTIME"```以及```"DHCP_HOSTNAME"```。

</br>

* ```"Type"```(integer: 1 byte, required): ```"DHCP_MESSAGETYPE"```, ```"DHCP_CLIENTID"```, ```"DHCP_REQUESTED_IP_ADDRESS"```, ```"DHCP_PARAMREQUEST"```, ```"DHCP_PAD"```, ```"DHCP_SERVER"```, ```"DHCP_LEASETIME"```, ```"DHCP_SUBNETMASK"```, ```"DHCP_ROUTER"```, ```"DHCP_DNS_SERVER"```, ```"DHCP_NTP_SERVER"```, ```"DHCP_RENEWTIME"```, ```"DHCP_REBINDTIME"``` and ```"DHCP_HOSTNAME"``` are available.


###DHCPv4 Option DHCP_MESSAGETYPE(Message Type, 53)
* ```"Length"```(integer: 1 byte, optinoal, default: 1)。
* ```"Message"```(integer: 1 byte, required)：另外可用```"DHCP_MSGDISCOVER"```、```"DHCP_MSGOFFER"```、```"DHCP_MSGREQUEST"```、```"DHCP_MSGDECLINE"```、```"DHCP_MSGACK"```、```"DHCP_MSGNACK"```以及```"DHCP_MSGINFORM"```。

</br>

* ```"Length"```(integer: 1 byte, optinoal, default: 1).
* ```"Message"```(integer: 1 byte, required): ```"DHCP_MSGDISCOVER"```, ```"DHCP_MSGOFFER"```, ```"DHCP_MSGREQUEST"```, ```"DHCP_MSGDECLINE"```, ```"DHCP_MSGACK"```, ```"DHCP_MSGNACK"``` and ```"DHCP_MSGINFORM"``` are available.

###DHCPv4 Option DHCP_CLIENTID(Client ID, 61)
* ```"Length"```(integer: 1 byte, optional, default: 7)：```"Type"```(1) + Mac address(6) = 7。
* ```"Hardware Address Type"```(integer: 1 byte, optional, default: "0x1")：預設0x1表示乙太網路。
* ```"Client Hardware Address"```(address, optional, default: "myself")。

</br>

* ```"Length"```(integer: 1 byte, optional, default: 7): ```"Type"```(1) + Mac address(6) = 7.
* ```"Hardware Address Type"```(integer: 1 byte, optional, default: "0x1"): Default 0x1 means ethernet.
* ```"Client Hardware Address"```(address, optional, default: "myself").

###DHCPv4 Option DHCP\_REQUESTED\_SERVER(Requested IP Address, 50)
* ```"Length"```(integer: 1 byte, optional, default: 4)。
* ```"Requested IP Address"```(address, optional, default: "0.0.0.0")。

</br>

* ```"Length"```(integer: 1 byte, optional, default: 4).
* ```"Requested IP Address"```(address, optional, default: "0.0.0.0").

###DHCPv4 Option DHCP_PARAMREQUEST(Parameter, 55)
* ```"Length"```(integer: 1 byte, optional, depends: "List")：預設為```"List"```長度。
* ```"List"```(array, required)：陣列內除了整數以外，能夠使用```"DHCP_SUBNETMASK"```、```"DHCP_ROUTER"```、```"DHCP_DNS_SERVER"```以及```"DHCP_NTP_SERVER"```。

</br>

* ```"Length"```(integer: 1 byte, optional, depends: "List")：Default is length of ```"List"```.
* ```"List"```(array, required): Besides integer in array, ```"DHCP_SUBNETMASK"```, ```"DHCP_ROUTER"```, ```"DHCP_DNS_SERVER"``` and ```"DHCP_NTP_SERVER"``` are available.

###DHCPv4 Option DHCP_PAD(Padding, 0)

> 無。

</br>

> None.

###DHCPv4 Option DHCP_END(End, 255)

> 無。

</br>

> None.

###DHCPv4 Option DHCP_SERVER(DHCP Server Identifier, 54)
* ```"Length"```(integer: 1 byte, optional, default: 4)。
* ```"Server IP Address"```(address, required)。

</br>

* ```"Length"```(integer: 1 byte, optional, default: 4).
* ```"Server IP Address"```(address, required).

###DHCPv4 Option DHCP_SUBNETMASK(Subnet mask, 1)
* ```"Length"```(integer: 1 byte, optional, default: 4)。
* ```"Netmask"```(address, required)。

</br>

* ```"Length"```(integer: 1 byte, optional, default: 4).
* ```"Netmask"```(address, required).

###DHCPv4 Option DHCP_ROUTER(Router, 3)
* ```"Length"```(integer: 1 byte, optional, default: 4)。
* ```"Router IP Address"```(address, required)。

</br>

* ```"Length"```(integer: 1 byte, optional, default: 4).
* ```"Router IP Address"```(address, required).

###DHCPv4 Option DHCP\_DNS\_SERVER(DNS Server, 6)
* ```"Length"```(integer: 1 byte, optional, default: 4)。
* ```"DNS IP Address"```(address, required)。

</br>

* ```"Length"```(integer: 1 byte, optional, default: 4).
* ```"DNS IP Address"```(address, required).

###DHCPv4 Option DHCP\_NTP\_SERVER(NTP Server, 42)
* ```"Length"```(integer: 1 byte, optional, default: 4)。
* ```"NTP IP Address"```(address, required)。

</br>

* ```"Length"```(integer: 1 byte, optional, default: 4).
* ```"NTP IP Address"```(address, required).

###DHCPv4 Option DHCP_RENEWTIME(Renewal Time, 58)
* ```"Length"```(integer: 1 byte, optional, default: 4)。
* ```"Time"```(integer: 4 bytes, required)：單位秒。

</br>

* ```"Length"```(integer: 1 byte, optional, default: 4).
* ```"Time"```(integer: 4 bytes, required): Seconds.

###DHCPv4 Option DHCP_REBINDTIME(Rebind Time, 69)
* ```"Length"```(integer: 1 byte, optional, default: 4)。
* ```"Time"```(integer: 4 bytes, required)：單位秒。

</br>

* ```"Length"```(integer: 1 byte, optional, default: 4).
* ```"Time"```(integer: 4 bytes, required): Seconds.

###DHCPv4 Option DHCP_LEASETIME(IP Address Lease Time, 51)
* ```"Length"```(integer: 1 byte, optional, default: 4)。
* ```"Time"```(integer: 4 bytes, required)：單位秒。

</br>

* ```"Length"```(integer: 1 byte, optional, default: 4).
* ```"Time"```(integer: 4 bytes, required): Seconds.

###DHCPv4 Option DHCP_HOSTNAME(Hostname, 12)
* ```"Length"```(integer: 1 byte, optional, depends: "Hostname")：預設```"Hostname"```長度。
* ```"Hostname"```(string, required)。

</br>

* ```"Length"```(integer: 1 byte, optional, depends: "Hostname"): Default is length of ```"Hostname"```.
* ```"Hostname"```(string, required).

###DHCPv4 Options Example1
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

###DHCPv4 Options Example2
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