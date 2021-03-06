#!/bin/sh

#clear old file
rm -f Anubis.exe Anubis.log *.dep uac.manifest uac.rc

#generate manifest file
manifest=`cat <<"EOF"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
<security>
<requestedPrivileges>
<requestedExecutionLevel level="requireAdministrator"/>
</requestedPrivileges>
</security>
</trustInfo>
</assembly>
EOF
`
echo -e "$manifest" > uac.manifest

#generate resource file
rc=`cat <<"EOF"

#define RT_MANIFEST 24
#include <winuser.h>
1 RT_MANIFEST uac.manifest

EOF
`
echo -e "$rc" > uac.rc

#convert resource file
windres --input-format=rc -O coff -i uac.rc -o uac.res

#comiple and sign
g++ -o Anubis.exe -Wl,-gc-sections -static \
 -L /cygdrive/c/libnet-1.2-rc3-vs2015/lib/ \
 -L /cygdrive/c/libdnet-1.11-win32/lib/ \
 -L /cygdrive/c/WpdPack/Lib/ \
 -Wl,--start-group \
 *.o \
 -liphlpapi -ladvapi32 -lws2_32 \
 -lpacket -lwpcap -ldnet -lnet.lib \
 -lssl -lcrypto -lz \
  uac.res \
 -Wl,--end-group



#clear file
rm -f uac.manifest uac.rc *.o

./Anubis.exe --version