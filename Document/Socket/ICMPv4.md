#ICMPv4

ICMPv4表頭。

</br>

ICMPv4 header.

##ICMP(ICMPv4) header
* ```"Type"```(integer 1 byte, required)：另外可用```"ICMP_ECHO"```、```"ICMP_ECHOREPLY"```、```"ICMP_TIMXCEED"```、```"ICMP_UNREACH"```以及```"ICMP_REDIRECT"```。
* ```"Code"```(integer 1 byte, required)：另外可用```"ICMP_TIMXCEED_INTRANS"```、```"ICMP_TIMXCEED_REASS"```、```"ICMP_UNREACH_NET"```、```"ICMP_UNREACH_HOST"```、```"ICMP_UNREACH_PROTOCOL"```、```"ICMP_UNREACH_PORT"```、```"ICMP_UNREACH_NEEDFRAG"```、```"ICMP_UNREACH_SRCFAIL"```、```"ICMP_UNREACH_NET_UNKNOWN"```、```"ICMP_UNREACH_HOST_UNKNOWN"```、```"ICMP_UNREACH_ISOLATED"```、```"ICMP_UNREACH_NET_PROHIB"```、```"ICMP_UNREACH_HOST_PROHIB"```、```"ICMP_UNREACH_TOSNET"```、```"ICMP_UNREACH_TOSHOST"```、```"ICMP_UNREACH_FILTER_PROHIB"```、```"ICMP_UNREACH_HOST_PRECEDENCE"```、```"ICMP_UNREACH_PRECEDENCE_CUTOFF"```、```"ICMP_REDIRECT_NET"```、```"ICMP_REDIRECT_HOST"```、```"ICMP_REDIRECT_TOSNET"```以及```"ICMP_REDIRECT_TOSHOST"```。
* ```"Checksum"```(integer 2 bytes, optional, default: "auto")：```"auto"```與0都表示自動計算。
* ```"Identifier"```(integer 2 bytes, optional, default: 0)：可以用```"random()"```取得亂數。
* ```"Sequence number"```(integer 2 bytes, optional, default: 0)：可以簡寫成```"seq"```，可以用```"random()"```取得亂數。
* ```"Next MTU"```(integer 2 bytes, optional, default: 0)：該欄位會在```"Type="ICMP_UNREACH"```且```"Code"="ICMP_UNREACH_NEEDFRAG"```時才有作用。
* ```"Gateway"```(address, optional, default: "0.0.0.0")。

> 1. 因為ICMP Redirect封包中(最後的)IP表頭後所帶的資料只有8 bytes，如果該資料的有```"Checksum"```欄位且使用```"auto```"，則會用那8 bytes計算Checksum。
> 2. 如果已經使用了ICMP Redirect，不應該再繼續使用"Payload"欄位。

</br>

* ```"Type"```(integer 1 byte, required): ```"ICMP_ECHO"```, ```"ICMP_ECHOREPLY"```, ```"ICMP_TIMXCEED"```, ```"ICMP_UNREACH"``` and ```"ICMP_REDIRECT"``` are available.
* ```"Code"```(integer 1 byte, required): ```"ICMP_TIMXCEED_INTRANS"```, ```"ICMP_TIMXCEED_REASS"```, ```"ICMP_UNREACH_NET"```, ```"ICMP_UNREACH_HOST"```, ```"ICMP_UNREACH_PROTOCOL"```, ```"ICMP_UNREACH_PORT"```, ```"ICMP_UNREACH_NEEDFRAG"```, ```"ICMP_UNREACH_SRCFAIL"```, ```"ICMP_UNREACH_NET_UNKNOWN"```, ```"ICMP_UNREACH_HOST_UNKNOWN"```, ```"ICMP_UNREACH_ISOLATED"```, ```"ICMP_UNREACH_NET_PROHIB"```, ```"ICMP_UNREACH_HOST_PROHIB"```, ```"ICMP_UNREACH_TOSNET"```, ```"ICMP_UNREACH_TOSHOST"```, ```"ICMP_UNREACH_FILTER_PROHIB"```, ```"ICMP_UNREACH_HOST_PRECEDENCE"```, ```"ICMP_UNREACH_PRECEDENCE_CUTOFF"```, ```"ICMP_REDIRECT_NET"```, ```"ICMP_REDIRECT_HOST"```, ```"ICMP_REDIRECT_TOSNET"``` and ```"ICMP_REDIRECT_TOSHOST"``` are available.
* ```"Checksum"```(integer 2 bytes, optional, default: "auto"): ```"auto"``` and 0 means auto calculate.
* ```"Identifier"```(integer 2 bytes, optional, default: 0): ```"random()"``` is available.
* ```"Sequence number"```(integer 2 bytes, optional, default: 0): It can be shortened to ```"seq"```. ```"random()"``` is available.
* ```"Next MTU"```(integer 2 bytes, optional, default: 0): When ```"Type="ICMP_UNREACH"``` and ```"Code"="ICMP_UNREACH_NEEDFRAG"```, is available.
* ```"Gateway"```(address, optional, default: "0.0.0.0").

> 1. The data of ICMP redirect carry length is only 8 bytes. If ```"Checksum"``` use ```"auto"```, will calculate checksum by the 8 bytes.
> 2. If ICMP redirect exist, "Payload" should not be appeared.

###ICMP(ICMPv4) Example1

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

##ICMP(ICMPv4) Example2

```
{
    "ICMP": {
        "Type": "ICMP_REDIRECT",
        "Code": "ICMP_REDIRECT_HOST",
        "Checksum": "auto",
        "Gateway": "Default-Route"
    }
}
```

##ICMP(ICMPv4) Example3

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

##ICMP(ICMPv4) Example4

```
{
    "ICMP": {
        "Type": "ICMP_TIMXCEED",
        "Code": 0,
        "Checksum": "auto"
    }
}
```