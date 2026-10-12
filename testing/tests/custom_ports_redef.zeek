# @TEST-EXEC: zeek ${PACKAGE} -e 'redef OMRON_FINS::omron_fins_ports_tcp += { 12346/tcp }; redef OMRON_FINS::omron_fins_ports_udp += { 12346/udp }; event zeek_init() &priority=-5 { print fmt("%s %s %s %s", 12346/tcp in Analyzer::registered_ports(Analyzer::ANALYZER_OMRON_FINS_TCP), 12346/tcp in likely_server_ports, 12346/udp in Analyzer::registered_ports(Analyzer::ANALYZER_OMRON_FINS_UDP), 12346/udp in likely_server_ports); terminate(); }' | grep -qx 'T T T T'
#
# @TEST-DOC: Verify set redefinitions feed analyzer registration and direction inference.
