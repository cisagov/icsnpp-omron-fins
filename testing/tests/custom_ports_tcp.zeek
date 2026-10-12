# @TEST-EXEC: python3 ${DIST}/testing/scripts/rewrite-fins-port.py --input ${TRACES}/omron_fins_tcp_commands_responses.pcap --output tcp-custom.pcap --transport tcp
# @TEST-EXEC: python3 ${DIST}/testing/scripts/rewrite-fins-port.py --input ${TRACES}/omron_fins_tcp_commands_responses.pcap --output tcp-custom-server-first.pcap --transport tcp --direction server-first
# @TEST-EXEC: mkdir baseline configured server-first
# @TEST-EXEC: cd baseline && zeek -C -r ../tcp-custom.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: test ! -e baseline/omron_fins_general.log
# @TEST-EXEC: cd configured && env ZEEK_OMRON_FINS_PORTS=12345/tcp zeek -C -r ../tcp-custom.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: test $(zeek-cut < configured/omron_fins_general.log | wc -l) -eq 16
# @TEST-EXEC: cd server-first && env ZEEK_OMRON_FINS_PORTS=12345/tcp zeek -C -r ../tcp-custom-server-first.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: test $(zeek-cut < server-first/omron_fins_general.log | wc -l) -eq 8
#
# @TEST-DOC: Verify TCP custom-port activation and server-first direction inference.
