
include $(top_srcdir)/Makefile.am.common

SUBDIRS = missing parser writer model
sbin_PROGRAMS = anubis
anubis_SOURCES = missing/snprintf.c \
                missing/strdup.c \
                missing/strlcat.c \
                missing/strlcpy.c \
                missing/strcasecmp.c \
                parser/anubis_parse_icmp.c \
                parser/anubis_parse_rip.c \
                parser/anubis_parse_wol.c \
                parser/anubis_parse_arp.c \
                parser/anubis_parse_ipv4.c \
                parser/anubis_parse_socket.c \
                parser/anubis_parse_dhcpv4.c \
                parser/anubis_parse_message.c \
                parser/anubis_parse_tcp.c \
                parser/anubis_parse_ethernet.c \
                parser/anubis_parse_other.c \
                parser/anubis_parse_udp.c \
                writer/anubis_write_data_link_or_network.c \
                writer/anubis_write_transport.c \
                writer/anubis_write_application.c \
                model/anubis_model_arping.c \
                model/anubis_model_arpoison.c \
                json.c \
                anubis_defaults.c \
                anubis_parser.c \
                anubis_stream.c \
                anubis_time.c \
                anubis_value_converter.c \
                anubis_writer.c \
                anubis_dumper.c \
                anubis_libnet_extension.c \
                anubis_value_checker.c \
                anubis_extra.c \
                anubis_model.c \
                anubis.c 