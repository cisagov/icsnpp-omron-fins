# @TEST-EXEC: python3 ${DIST}/testing/scripts/rewrite-fins-port.py --input ${TRACES}/omron.pcap --output udp-custom.pcap --transport udp
# @TEST-EXEC: python3 ${DIST}/testing/scripts/rewrite-fins-port.py --input ${TRACES}/omron.pcap --output udp-custom-reverse.pcap --transport udp --direction reverse
# @TEST-EXEC: mkdir baseline configured reverse
# @TEST-EXEC: cd baseline && zeek -C -r ../udp-custom.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: test ! -e baseline/omron_fins_general.log
# @TEST-EXEC: cd configured && env ZEEK_OMRON_FINS_PORTS=12345/udp zeek -C -r ../udp-custom.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: test $(zeek-cut < configured/omron_fins_general.log | wc -l) -eq 243
# @TEST-EXEC: cd reverse && env ZEEK_OMRON_FINS_PORTS=12345/udp zeek -C -r ../udp-custom-reverse.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: test $(zeek-cut < reverse/omron_fins_general.log | wc -l) -eq 243
#
# @TEST-DOC: Verify UDP custom-port activation and reverse-direction inference.
