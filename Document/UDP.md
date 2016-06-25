#UDP

UDP表頭。

</br>

UDP header.

##UDP header
* ```"Source Port"```(integer 2 bytes, required)：可以用```"random()"```取得亂數，另外可以使用```port()```填入參數。
* ```"Destination Port"```(integer 2 bytes, required)：可以用```"random()"```取得亂數，另外可以使用```port()```填入參數。
* ```"Checksum"```(integer 2 bytes, optional, default: "auto")：```"auto"```與0都表示自動計算。
* ```"Length"```(integer 2 bytess, optional, default: "auto")：```"auto"```與0都表示自動計算。

</br>

* ```"Source Port"```(integer 2 bytes, required): ```"random()"``` and ```port()``` are available.
* ```"Destination Port"```(integer 2 bytes, required): ```"random()"``` and ```port()``` are available.
* ```"Checksum"```(integer 2 bytes, optional, default: "auto"): ```"auto"``` and 0 means auto calculate.
* ```"Length"```(integer 2 bytess, optional, default: "auto"): ```"auto"``` and 0 means auto calculate.

###UDP Example

```
{
    "UDP": {
        "Source Port": "random(dynamic)",
        "Destination Port": "port(RIP)",
        "Length": "0x8",
        "Checksum": "auto"
    }
}
```