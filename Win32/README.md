#Anubis v1.1.2(Windows)

Windows版本目前不穩定，大致上幾乎所有功能正常。

>懶得修改。

##Usage

1. 安裝[Winpcap](Dependencies/WpdPack/WinPcap_4_1_3.exe)。
2. 複製[目錄](Release/)內*.dll到C:\Windows\System32內。
3. 執行[Anubis](Release/Anubis.exe)。

##Bugs
1. Transport Socket的UDP無法廣播。
2. Transport Socket的TCP無法選擇特定device送出。
3. Receive packet option中的Timeout似乎無法使用。