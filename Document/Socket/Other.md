#Other

其他類型的表頭。

</br>

Other header.

##Payload
* ```"Payload"```(string, optional, default: NULL)：封包最後面攜帶的資料。
* ```"Payload length"```(integer 2 bytes, optional, depends: "Payload")：```"Payload"```長度，如果沒給長度會自動計算；如果```"Payload length"```超過```"Payload"```實際長度，會以```"Payload length"```為主。

> Payload是封包最上層的資料，所以只能出現一次，如果出現兩次以上，會以最後一次為主；如果要使用沒有提供的協定，可以使用Payload的方式建構。

</br>

* ```"Payload"```(string, optional, default: NULL): Last data of packet carring.
* ```"Payload length"```(integer 2 bytes, optional, depends: "Payload"): Length of ```"Payload"```. If not given, it will auto calculate. If ```"Payload length"``` is larger than ```"Payload"``` exactly length, use ```"Payload length"```.

> Payload is the last data, appear once only. If twice, last one is mainly. If you want use protocol but not provided, use Payload to build.

###Payload Example

```
{
    "Payload": {
        "Payload": "This is payload data",
        "Payload Length": 20
    }
}
```

##Raw Data
* ```"Data"```(string, optional, default: NULL)：封包最後面攜帶的資料。
* ```"Data length"```(integer 2 bytes, optional, depends: "Data")：```"Data"```長度，如果沒給長度會自動計算；如果```"Data length"```超過```"Data"```實際長度，會以```"Data length"```為主。

> Raw Data可以出現在任何地方，跟Payload類似，只是沒有出現限制。

</br>

* ```"Data"```(string, optional, default: NULL): Last data of packet carring.
* ```"Data length"```(integer 2 bytes, optional, depends: "Data"): Length of ```"Data"```. If not given, it will auto calculate. If ```"Data length"``` is larger than ```"Data"``` exactly length, use ```"Data length"```.

> Raw Data can appear anywhere, similar to Payload.

###Raw Data Example

```
{
    "Raw Data": {
        "Data": "This is data",
        "Data Length": 12
    }
}
```