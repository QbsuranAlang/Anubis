#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# autoconf version
AC_PREREQ([2.69])

# init automake
# AC_CONFIG_AUX_DIR([config])
# AC_SUBST(ac_aux_dir, [config])

# init autoconf 
AC_INIT(anubis, 1.1.2, jr89197@hotmail.com)
AM_INIT_AUTOMAKE([subdir-objects])

# main program
AC_CONFIG_SRCDIR([src/anubis.c])

# config.h 
AC_CONFIG_HEADERS([include/config.h])

# default install dir
AC_PREFIX_DEFAULT(/usr)

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O 
AC_PROG_INSTALL

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/param.h sys/socket.h sys/time.h unistd.h wchar.h stddef.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_CHECK_FUNCS([getcwd gettimeofday memmove memset pow select socket strcasecmp strchr strdup strerror strncasecmp strlcat strlcpy snprintf memchr])

AC_ARG_ENABLE([64-bit],
    [AS_HELP_STRING([--enable-64-bit], [for search OpenSSL library path])],
    [enable_64bit="$enableval"],
    [enable_64bit=auto]
)

# Checks for libnet
AC_MSG_CHECKING(for libnet)
AC_ARG_WITH(libnet,
[AS_HELP_STRING([--with-libnet=DIR], [use libnet build directory])],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     #AC_MSG_RESULT($withval)
     if test -f $withval/include/libnet.h -a -f $withval/lib/libnet.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
    LIBNET_CFLAGS="-I$withval/include"
    LIBNET_LDFLAGS="-L$withval/lib"
    LIBNET_LIBS="-lnet"
     else
        AC_ERROR(libnet.h or libnet.a not found in $withval)
     fi
     AC_MSG_RESULT(yes)
     ;;
  esac ],
  [
  if test -f ${prefix}/include/libnet.h; then
     LIBNET_CFLAGS="-I${prefix}/include"
     LIBNET_LDFLAGS="-L${exec_prefix}/lib"
     LIBNET_LIBS="-lnet"
  else
    TMP=$LIBS
    LIBS="-lnet $LIBS"
    AC_TRY_LINK([#include <libnet.h>], libnet_init("","",""),
    LIBNET_FOUND=1,LIBNET_FOUND=0)
    LIBS=$TMP
    if test $LIBNET_FOUND = 1 ; then
        LIBNET_LIBS="-lnet"
    else
        AC_ERROR(libnet not found)
    fi
  fi
  AC_MSG_RESULT(yes)
  ]
)

# Checks for libpcap
AC_MSG_CHECKING(for libpcap)
AC_ARG_WITH(libpcap,
[AS_HELP_STRING([--with-libpcap=DIR], [use libpcap build directory])],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     #AC_MSG_RESULT($withval)
     if test -f $withval/include/pcap.h -a -f $withval/lib/libpcap.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
    LIBPCAP_CFLAGS="-I$withval/include"
    LIBPCAP_LDFLAGS="-L$withval/lib"
    LIBPCAP_LIBS="-lpcap"
     else
        AC_ERROR(pcap.h or libpcap.a not found in $withval)
     fi
     AC_MSG_RESULT(yes)
     ;;
  esac ],
  [
  if test -f ${prefix}/include/pcap.h; then
     LIBPCAP_CFLAGS="-I${prefix}/include"
     LIBPCAP_LDFLAGS="-L${exec_prefix}/lib"
     LIBPCAP_LIBS="-lpcap"
  else
    TMP=$LIBS
    LIBS="-lpcap $LIBS"
    AC_TRY_LINK([#include <pcap.h>], pcap_open_live("","","","",""),
    LIBPCAP_FOUND=1,LIBPCAP_FOUND=0)
    LIBS=$TMP
    if test $LIBPCAP_FOUND = 1 ; then
        LIBPCAP_LIBS="-lpcap"
    else
        AC_ERROR(libpcap not found)
    fi
  fi
  AC_MSG_RESULT(yes)
  ]
)

# Checks for libdnet
AC_MSG_CHECKING(for libdnet)
AC_ARG_WITH(libdnet,
[AS_HELP_STRING([--with-libdnet=DIR], [use libdnet build directory])],
[ 
case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     #AC_MSG_RESULT($withval)
     if test -f $withval/include/dnet.h -a -f $withval/lib/libdnet.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
    DNET_CFLAGS="-I$withval/include"
    DNET_LDFLAGS="-L$withval/lib"
    DNET_LIBS="-ldnet"
     else
        AC_ERROR(libdnet.h or libdnet.a not found in $withval)
     fi
     AC_MSG_RESULT(yes)
     ;;
  esac ],
  [
  if test -f ${prefix}/include/dnet.h; then
     DNET_CFLAGS="-I${prefix}/include"
     DNET_LDFLAGS="-L${exec_prefix}/lib"
     DNET_LIBS="-ldnet"
  else
    TMP=$LIBS
    LIBS="-ldnet $LIBS"
    AC_TRY_LINK([#include <dnet.h>], arp_open(),
    DNET_FOUND=1,DNET_FOUND=0)
    LIBS=$TMP
    if test $DNET_FOUND = 1 ; then
        DNET_LIBS="-ldnet"
    else
        AC_ERROR(libdnet not found)
    fi
  fi
  AC_MSG_RESULT(yes)
  ]
)

# Checks for OpenSSL
AC_MSG_CHECKING(for OpenSSL)
AC_ARG_WITH(openssl,
[AS_HELP_STRING([--with-openssl=DIR], [use OpenSSL build directory])],
[ 
case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     #AC_MSG_RESULT($withval)
     if test -f $withval/include/openssl/ssl.h -a -f $withval/lib/libssl.a -o -f $withval/lib64/libssl.a ; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
    SSL_CFLAGS="-I$withval/include"
    if test "x$enable_64bit" = xyes ; then
        SSL_LDFLAGS="-L$withval/lib64"
    else
        SSL_LDFLAGS="-L$withval/lib"
    fi
    SSL_LIBS="-lssl"
    else
        AC_ERROR(openssl/ssl.h or libssl.a not found in $withval)
    fi

     if test -f $withval/include/openssl/rsa.h -a -f $withval/lib/libcrypto.a -o -f $withval/lib64/libcrypto.a ; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
    CRYPTO_CFLAGS="-I$withval/include"
    if test "x$enable_64bit" = xyes ; then
        CRYPTO_LDFLAGS="-L$withval/lib64"
    else
        CRYPTO_LDFLAGS="-L$withval/lib"
    fi
    CRYPTO_LIBS="-lcrypto"
     else
        AC_ERROR(openss/rsa.h or libcrpto.a not found in $withval)
     fi
     
     AC_MSG_RESULT(yes)
     ;;
  esac ],
  [
  if test -f ${prefix}/include/openssl/ssl.h; then
    SSL_CFLAGS="-I${prefix}/include"
    if test "x$enable_64bit" = xyes ; then
        SSL_LDFLAGS="-L${exec_prefix}/lib64"
    else
        SSL_LDFLAGS="-L${exec_prefix}/lib"
    fi
     SSL_LIBS="-lssl"
  else
    TMP=$LIBS
    LIBS="-lssl $LIBS"
    AC_TRY_LINK([#include <openss/ssl.h>], SSL_new(""),
    LIBSSL_FOUND=1,LIBSSL_FOUND=0)
    LIBS=$TMP
    if test $LIBSSL_FOUND = 1 ; then
        SSL_LIBS="-lssl"
    else
        AC_ERROR(libssl.a not found)
    fi
  fi

  if test -f ${prefix}/include/openssl/rsa.h; then
     CRYPTO_CFLAGS="-I${prefix}/include"
     if test "x$enable_64bit" = xyes ; then
        CRYPTO_LDFLAGS="-L${exec_prefix}/lib64"
    else
        CRYPTO_LDFLAGS="-L${exec_prefix}/lib"
    fi
     CRYPTO_LIBS="-lcrypto"
  else
    TMP=$LIBS
    LIBS="-lcrypto $LIBS"
    AC_TRY_LINK([#include <openss/rsa.h>], RSA_new(),
    LIBCRYPTO_FOUND=1,LIBCRYPTO_FOUND=0)
    LIBS=$TMP
    if test $LIBCRYPTO_FOUND = 1 ; then
        CRYPTO_LIBS="-lcrypto"
    else
        AC_ERROR(libcrypto.a not found)
    fi
  fi

  AC_MSG_RESULT(yes)
  ]
)

# Set flags
TOTAL_CFLAGS="$CFLAGS -std=c99 -D _GNU_SOURCE -include config.h $LIBPCAP_CFLAGS $LIBNET_CFLAGS $DNET_CFLAGS $SSL_CFLAGS $CRYPTO_CFLAGS"

TOTAL_LDFLAGS="$LDFLAGS $LIBPCAP_LDFLAGS $LIBNET_LDFLAGS $DNET_LDFLAGS $SSL_LDFLAGS $CRYPTO_LDFLAGS"

TOTAL_LIBS="$LIBS -lm $LIBPCAP_LIBS $LIBNET_LIBS $DNET_LIBS $SSL_LIBS $CRYPTO_LIBS"

AC_SUBST(CFLAGS, $[TOTAL_CFLAGS])
AC_SUBST(LDFLAGS, $[TOTAL_LDFLAGS])
AC_SUBST(LIBS, $[TOTAL_LIBS])

# output file
AC_CONFIG_FILES([ 
  Makefile
  include/Makefile
  src/Makefile
  src/missing/Makefile
  doc/Makefile
  doc/man/Makefile
  doc/man/man1/Makefile
]) 

AC_OUTPUT
