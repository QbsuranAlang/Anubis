#Message

網路訊息格式。

</br>

Internet message format.

##Internet Message Format(Request)
* ```"Method"```(string, required)。
* ```"URL"```(string, required)。
* ```"Version"```(string, optional, default: "HTTP/1.1")。

> ```"Request"```需要為object。

</br>

* ```"Method"```(string, required).
* ```"URL"```(string, required).
* ```"Version"```(string, optional, default: "HTTP/1.1").

> ```"Request"``` should be an object.

##Internet Message Format(Response)
* ```"Version"```(string, optional, default: "HTTP/1.1")。
* ```"Status Code"```(integer 4 bytes, depends: "Phrase")。
* ```"Phrase"```(string, depends: "Status Code")。

> ```"Response"```需要為object，```"Status Code"```和"```"Phrase"```如果只填入其中一個，會自動互相填入另一個。

</br>

* ```"Version"```(string, optional, default: "HTTP/1.1").
* ```"Status Code"```(integer 4 bytes, depends: "Phrase").
* ```"Phrase"```(string, depends: "Status Code").

> ```"Response"``` should be an object. If only fill one of ```"Status Code"``` and ```"Phrase"```, autofill another one.

###Corresponding table
```
100, "Continue"
101, "Switching Protocols"
102, "Processing"
200, "OK"
201, "Created"
202, "Accepted"
203, "Non-Authoritative Information"
204, "No Content"
205, "Reset Content"
206, "Partial Content"
207, "Multi-Status"
208, "Already Reported"
226, "IM Used"
300, "Multiple Choices"
301, "Moved Permanently"
302, "Found"
303, "See Other"
304, "Not Modified"
305, "Use Proxy"
306, "Switch Proxy"
307, "Temporary Redirect"
308, "Permanent Redirect"
400, "Bad Request"
401, "Unauthorized"
402, "Payment Required"
403, "Forbidden"
404, "Not Found"
405, "Method Not Allowed"
406, "Not Acceptable"
407, "Proxy Authentication Required"
408, "Request Timeout"
409, "Conflict"
410, "Gone"
411, "Length Required"
412, "Precondition Failed"
413, "Payload Too Large"
414, "URI Too Long"
415, "Unsupported Media Type"
416, "Range Not Satisfiable"
417, "Expectation Failed"
418, "I'm a teapot"
421, "Misdirected Request"
422, "Unprocessable Entity"
423, "Locked"
424, "Failed Dependency"
426, "Upgrade Required"
428, "Precondition Required"
429, "Too Many Requests"
431, "Request Header Fields Too Large"
451, "Unavailable For Legal Reasons"
500, "Internal Server Error"
501, "Not Implemented"
502, "Bad Gateway"
503, "Service Unavailable"
504, "Gateway Timeout"
505, "HTTP Version Not Supported"
506, "Variant Also Negotiates"
507, "Insufficient Storage"
508, "Loop Detected"
510, "Not Extended"
511, "Network Authentication Required"

//Unofficial codes
103, "Checkpoint"
420, "Method Failure"
420, "Enhance Your Calm"
450, "Blocked by Windows Parental Controls"
498, "Invalid Token"
499, "Token Required"
499, "Request has been forbidden by antivirus"
509, "Bandwidth Limit Exceeded"
530, "Site is frozen"
440, "Login Timeout"
449, "Retry With"
451, "Redirect"
444, "No Response"
495, "SSL Certificate Error"
496, "SSL Certificate Required"
497, "HTTP Request Sent to HTTPS Port"
499, "Client Closed Request"
520, "Unknown Error"
521, "Web Server Is Down"
522, "Connection Timed Out"
523, "Origin Is Unreachable"
524, "A Timeout Occurred"
525, "SSL Handshake Failed"
526, "Invalid SSL Certificate"
0, "Undefined"
```

> https://zh.wikipedia.org/wiki/HTTP%E7%8A%B6%E6%80%81%E7%A0%81

##Internet Message Format(Field)
* ```"Keys"```(array, required)：只能使用字串表示。
* ```"Values"```(array, required)：只能使用字串表示。

> ```"Keys"```和```"Values"```互相搭配使用，陣列數量必須相同。

</br>

* ```"Keys"```(array, required): String only.
* ```"Values"```(array, required): String only.

> ```"Keys"``` and ```"Values"``` Corresponding to each other, length of array should the same.

##SSDP

> SSDP使用Internet Message Format(與HTTP相同)，都使用兩個object：```"Request"```或```"Response"```以及```"Field"```，其中```"Request"```和```"Response"```同時只能存在一個。

</br>

> SSDP use Internet Message Format(Same as HTTP). Both use two object: ```"Request"``` or ```"Response"``` and ```"Field"```. ```"Request"``` and ```"Response"``` should be appear one of them at the same time.

###SSDP Example

```
{
    "SSDP": {
        "Request": {
            "Method": "M-SEARCH",
            "URL": "*",
            "Version": "HTTP/1.1"
        },
        "Field": {
            "Keys": [
                "HOST",
                "MAN",
                "MX",
                "ST"
            ],
            "Values": [
                "239.255.255.250:1900",
                "\"ssdp:discover\"",
                "2",
                "ssdp:all"
            ]
        }
    }
}
```

##HTTP

> HTTP使用Internet Message Format，使用兩個object：```"Request"```或```"Response"```以及```"Field"```，其中```"Request"```和```"Response"```同時只能存在一個。

</br>

> HTTP use Internet Message Format. Both use two object: ```"Request"``` or ```"Response"``` and ```"Field"```. ```"Request"``` and ```"Response"``` should be appear one of them at the same time.

###HTTP Example

```
{
    "HTTP": {
        "Request": {
            "Method": "GET",
            "URL": "/",
            "Version": "HTTP/1.1"
        },
        "Field": {
            "Keys": [
                "Host",
                "Connection",
                "Accept",
                "Upgrade-Insecure-Requests",
                "User-Agent",
                "Accept-Encoding",
                "Accept-Language"
            ],
            "Values": [
                "translate.google.com.tw",
                "keep-alive",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "1",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36",
                "gzip, deflate, sdch",
                "zh-TW,zh;q=0.8,en-US;q=0.6,en;q=0.4"
            ]
        }
    }
}
```