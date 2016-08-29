#TCP and TCP options

TCP和TCP options表頭。

</br>

TCP and TCP options header.

##TCP header
* ```"Source Port"```(integer 2 bytes, required)：可以用```"random()"```取得亂數，另外可以使用```port()```填入參數。
* ```"Destination Port"```(integer 2 bytes, required)：可以用```"random()"```取得亂數，另外可以使用```port()```填入參數。
* ```"Sequence number"```(integer 4 bytes, optional, default: 0)：可以簡寫成```"seq"```。
* ```"Acknowledgment number"```(integer 4 bytes, optional, default: 0)：可以簡寫成```"ack"```。
* ```"Flags"```(others 8 bits, optional, default: 0)：只能使用```"TH_FIN"```、```"TH_SYN"```、```"TH_RST"```、```"TH_PUSH"```、```"TH_ACK"```、```"TH_URG"```、```"TH_ECE"```和```"TH_CWR"```，能夠用"|"組合，例如```"TH_SYN | TH_ACK"```。
* ```"Window"```(integer 2 bytes, optional, default: 0)。
* ```"Checksum"```(integer 2 bytes, optional, default: "auto")：```"auto"```與0都表示自動計算。
* ```"Urgent Pointer"```(integer 2 bytes, optional, default: 0)。

</br>

* ```"Source Port"```(integer 2 bytes, required): ```"random()"``` and ```port()``` are available.
* ```"Destination Port"```(integer 2 bytes, required): ```"random()"``` and ```port()``` are available.
* ```"Sequence number"```(integer 4 bytes, optional, default: 0): It can be shortened to ```"seq"```.
* ```"Acknowledgment number"```(integer 4 bytes, optional, default: 0): It can be shortened to ```"ack"```.
* ```"Flags"```(others 8 bits, optional, default: 0): ```"TH_FIN"```, ```"TH_SYN"```, ```"TH_RST"```, ```"TH_PUSH"```, ```"TH_ACK"```, ```"TH_URG"```, ```"TH_ECE"``` and ```"TH_CWR"``` only. "|" is available, example: ```"TH_SYN | TH_ACK"```.
* ```"Window"```(integer 2 bytes, optional, default: 0).
* ```"Checksum"```(integer 2 bytes, optional, default: "auto"): ```"auto"``` and 0 means auto calculate.
* ```"Urgent Pointer"```(integer 2 bytes, optional, default: 0).

###TCP Example

```
{
    "TCP": {
        "Source Port": "random(dynamic)",
        "Destination Port": "80",
        "Sequence number": "0x12345678",
        "Acknowledgment number": "0x87654321",
        "Flags": "TH_SYN | TH_FIN | TH_PUSH",
        "Window": "0xabcd",
        "Checksum": "auto",
        "Urgent Pointer": "0"
    }
}
```

##TCP Options
* ```"Type"```(integer 1 byte, required)：可使用```"TCPOPT_MAXSEG"```、```"TCPOPT_SACK_PERMITTED"```、```"TCPOPT_WINDOW"```、```"TCPOPT_NOP"```、```"TCPOPT_EOL"```。

> TCP Options必須為4的倍數。

</br>

* ```"Type"```(integer 1 byte, required): ```"TCPOPT_MAXSEG"```, ```"TCPOPT_SACK_PERMITTED"```, ```"TCPOPT_WINDOW"```, ```"TCPOPT_NOP"```, ```"TCPOPT_EOL"``` are available.

> TCP Options must be times of 4.

###TCP Option TCPOPT_MAXSEG(Maximum Segment Size, 2)
* ```"Length"```(integer 1 byte, optional, default: 4)。
* ```"MSS Value"```(integer 2 bytes, required)。

</br>

* ```"Length"```(integer 1 byte, optional, default: 4).
* ```"MSS Value"```(integer 2 bytes, required).

##TCP Option TCPOPT\_SACK\_PERMITTED(SACK Permitted, 4)
* ```"Length"```(integer 1 byte, optional, default: 2)。

</br>

* ```"Length"```(integer 1 byte, optional, default: 2).

##TCP Option TCPOPT_WINDOW(Window Scale, 3)
* ```"Length"```(integer 1 byte, optional, default: 3)。
* ```"Shift count"```(integer 1 byte, required)。

</br>

* ```"Length"```(integer 1 byte, optional, default: 3).
* ```"Shift count"```(integer 1 byte, required).

##TCP Option TCPOPT_NOP(No Operation, 1)

> 無

</br>

> None.

##TCP Option TCPOPT_EOL(End of Line, 0)

> 無

</br>

> None.

###TCP Options Example

```
{
    "TCP Options": [
        {
            "Type": "TCPOPT_MAXSEG",
            "Length": 4,
            "MSS Value": 1460
        },
        {
            "Type": "TCPOPT_SACK_PERMITTED",
            "Length": 2
        },
        {
            "Type": "TCPOPT_WINDOW",
            "Length": 3,
            "Shift count": 7
        },
        {
            "Type": "TCPOPT_EOL"
        }
    ]
}
```