#Model Configuration

Anubis 模組和範例。

Model configuration and examples.

##Model configuration principle
1. 在**[Model-Template](Model-Template/)**目錄下有範例。
2. 只有兩個物件：```"Option"```和```"Model"```。
3. 並不是所有```"Option"```內的參數```"Model"```都會使用，```"Model"```會使用的```"Option"```參數都在各個文件內。
4. 標示成看情況的參數，並不是每個```"Model"```都會使用。

</br>

1. Examples in directory **[Model-Template](Model-Template/)**.
2. Two object only: ```"Option"``` and ```"Model"```.
3. It is not all parameters in ```"Option"``` are used by ```"Model"```. ```"Model"``` used parameters in ```"Option"``` are in the documents.
4. The parameters marked "depends" which mean not for every ```"Model"``` used.

##Option

* ```"Model"```(string, required)：Model名稱，目前可用```"arping"```以及```"arpoison"```。
* ```"_comment"```(string, optional)：註解。
* ```Save configuration to file```(string, optional, defualt: NULL)：是否要將產生的JSON組態檔儲存至檔案。
* ```"Amount"```(integer: 4 bytes, depends: "Model")：送出輪數(次數)。
* ```"Infinite loop"```(boolean, depends: "Model")：是否需要無窮迴圈，如果被設定則```"Amount"```無效果。
* ```"Interval"```(integer: 4 bytes, depends: "Model")：每輪間隔，單位豪秒(millisecond)。
* ```"Dump send packet"```(boolean, depends: "Model")：送出封包後，是否要將封包解析出來。
* ```"Dump receive packet"```(boolean, depends: "Model")：收到封包後，是否要將封包解析出來。
* ```"Receive Timeout"```(integer: 4 bytes, depends: "Model", default: 1)：接收超時時間，單位豪秒(millisecond)。
* ```Filter"```(string, depends: "Model")：根據每個```"Model"```會有預設值，使用libpcap過濾器表達式。
* ```"Device"```(string, depends: "Model")：要送出封包的device。

</br>

* ```"Model"```(string, required): Model name. Current: ```"arping"``` and ```"arpoison"``` are available.
* ```"_comment"```(string, optional): Comment.
* ```"Save configuration to file```(string, optional, defualt: NULL): Save generated JSON configuration to file.
* ```"Amount"```(integer: 4 bytes, depends: "Model"): Rounds.
* ```"Infinite loop"```(boolean, depends: "Model"): Infinite loop or not, if set, ```"Amount"``` is not effective.
* ```"Interval"```(integer: 4 bytes, depends: "Model"): Inerval of each round. Millisecond.
* ```"Dump send packet"```(boolean, depends: "Model"): After sending, dump send packet or not.
* ```"Dump receive packet"```(boolean, depends: "Model"): After receiving, dump received packet or not.
* ```"Receive Timeout"```(integer: 4 bytes, depends: "Model", default: 1): Receive timeout. Millisecond.
* ```Filter"```(string, depends: "Model"): Default value is according to ```"Model"```. Use libpcap filter expression.
* ```"Device"```(string, depends: "Model"): Device that packet send.

##Models
* [```"arping"```](Model/arping.md)
* [```"arpoison"```](Model/arpoison.md)