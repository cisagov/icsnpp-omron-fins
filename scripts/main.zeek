## main.zeek
##
## ICSNPP-OMRON_FINS
##
## Zeek script type/record definitions describing the information
## that will be written to the log files.
##

module OMRON_FINS;

export {
    const omron_fins_ports_udp: set[port] = { 9600/udp } &redef;
    const omron_fins_ports_tcp: set[port] = { 9600/tcp } &redef;

    # Additional Omron FINS ports supplied through the environment.
    global omron_fins_ports_str: string = getenv("ZEEK_OMRON_FINS_PORTS");

    redef enum Log::ID += { LOG_GENERAL_LOG, 
                            LOG_DETAIL_LOG, 
                            LOG_NETWORK_STATUS_READ_LOG,
                            LOG_DATA_LINK_STATUS_READ_LOG,
                            LOG_ERROR_LOG,
                            LOG_FILE_LOG };

    # Callback event for integrating with the file analysis framework
    global get_file_handle: function(c: connection, is_orig: bool): string;

    # Log policies for log filtering
    global log_policy_general: Log::PolicyHook;
    global log_policy_detail:  Log::PolicyHook;
    global log_policy_network_status_read:  Log::PolicyHook;
    global log_policy_data_link_status_read:  Log::PolicyHook;
    global log_policy_error:  Log::PolicyHook;
    global log_policy_file:  Log::PolicyHook;

    global log_general_log: event(rec: general_log);
    global log_detail_log: event(rec: detail_log);
    global log_network_status_read_log: event(rec: network_status_read_log);
    global log_data_link_status_read_log: event(rec: data_link_status_read_log);
    global log_error_log: event(rec: detail_error_log);
    global log_file_log: event(rec: detail_file_log);

    global emit_omron_fins_general_log: function(c: connection);
    global emit_omron_fins_detail_log: function(c: connection);
    global emit_omron_fins_network_status_read_log: function(c: connection);
    global emit_omron_fins_data_link_status_read_log: function(c: connection);
    global emit_omron_fins_error_log: function(c: connection);
    global emit_omron_fins_file_log: function(c: connection);

}

# redefine connection record to contain one of each of the omron_fins records
redef record connection += {
    omron_fins_proto: transport_proto &optional;
    omron_fins_general_log: general_log &optional;
    omron_fins_detail_log: detail_log &optional;
    omron_fins_network_status_read_log: network_status_read_log &optional;
    omron_fins_data_link_status_read_log: data_link_status_read_log &optional;
    omron_fins_error_log: detail_error_log &optional;
    omron_fins_file_log: detail_file_log &optional;
};

#Put protocol detection information here
event zeek_init() &priority=5 {
    local omron_fins_port: port;

    # register with the file analysis framework
    Files::register_protocol(Analyzer::ANALYZER_OMRON_FINS_UDP,
                            [$get_file_handle = OMRON_FINS::get_file_handle]);
    Files::register_protocol(Analyzer::ANALYZER_OMRON_FINS_TCP,
                            [$get_file_handle = OMRON_FINS::get_file_handle]);


    if (omron_fins_ports_str != "") {
        local omron_fins_custom_ports = split_string(omron_fins_ports_str, /,/);
        for (omron_fins_port_idx in omron_fins_custom_ports) {
            omron_fins_port = to_port(omron_fins_custom_ports[omron_fins_port_idx]);
            local omron_fins_prot = get_port_transport_proto(omron_fins_port);
            if (omron_fins_prot == tcp) {
                add omron_fins_ports_tcp[omron_fins_port];
                }
            else if (omron_fins_prot == udp) {
                add omron_fins_ports_udp[omron_fins_port];
                }
            }
        }

    # Populate this at initialization so ports added by later redef statements
    # and by ZEEK_OMRON_FINS_PORTS are included in the direction heuristic.
    for (omron_fins_port in omron_fins_ports_tcp) {
        add likely_server_ports[omron_fins_port];
        }

    for (omron_fins_port in omron_fins_ports_udp) {
        add likely_server_ports[omron_fins_port];
        }

    Analyzer::register_for_ports(Analyzer::ANALYZER_OMRON_FINS_UDP, omron_fins_ports_udp);
    Analyzer::register_for_ports(Analyzer::ANALYZER_OMRON_FINS_TCP, omron_fins_ports_tcp);

    # initialize logging streams for all omron_fins logs
    Log::create_stream(OMRON_FINS::LOG_GENERAL_LOG,
                      [$columns=general_log,
                      $ev=log_general_log,
                      $path="omron_fins_general",
                      $policy=log_policy_general]);

    Log::create_stream(OMRON_FINS::LOG_DETAIL_LOG,
                      [$columns=detail_log,
                      $ev=log_detail_log,
                      $path="omron_fins_detail",
                      $policy=log_policy_detail]);

    Log::create_stream(OMRON_FINS::LOG_NETWORK_STATUS_READ_LOG,
                      [$columns=network_status_read_log,
                      $ev=log_network_status_read_log,
                      $path="omron_fins_network_status_read",
                      $policy=log_policy_network_status_read]);

    Log::create_stream(OMRON_FINS::LOG_DATA_LINK_STATUS_READ_LOG,
                      [$columns=data_link_status_read_log,
                      $ev=log_data_link_status_read_log,
                      $path="omron_fins_data_link_status_read",
                      $policy=log_policy_data_link_status_read]);

    Log::create_stream(OMRON_FINS::LOG_ERROR_LOG,
                      [$columns=detail_error_log,
                      $ev=log_error_log,
                      $path="omron_fins_error",
                      $policy=log_policy_error]);

    Log::create_stream(OMRON_FINS::LOG_FILE_LOG,
                      [$columns=detail_file_log,
                      $ev=log_file_log,
                      $path="omron_fins_file",
                      $policy=log_policy_file]);
}

function emit_omron_fins_general_log(c: connection) {
    if (! c?$omron_fins_general_log )
        return;
    if ( c?$omron_fins_proto )
        c$omron_fins_general_log$proto = c$omron_fins_proto;
    Log::write(OMRON_FINS::LOG_GENERAL_LOG, c$omron_fins_general_log);
}

function emit_omron_fins_detail_log(c: connection) {
    if (! c?$omron_fins_detail_log )
        return;

    Log::write(OMRON_FINS::LOG_DETAIL_LOG, c$omron_fins_detail_log);
}

function emit_omron_fins_network_status_read_log(c: connection) {
    if (! c?$omron_fins_network_status_read_log )
        return;

    Log::write(OMRON_FINS::LOG_NETWORK_STATUS_READ_LOG, c$omron_fins_network_status_read_log);
}

function emit_omron_fins_data_link_status_read_log(c: connection) {
    if (! c?$omron_fins_data_link_status_read_log )
        return;

    Log::write(OMRON_FINS::LOG_DATA_LINK_STATUS_READ_LOG, c$omron_fins_data_link_status_read_log);
}

function emit_omron_fins_error_log(c: connection) {
    if (! c?$omron_fins_error_log )
        return;

    Log::write(OMRON_FINS::LOG_ERROR_LOG, c$omron_fins_error_log);
}

function emit_omron_fins_file_log(c: connection) {
    if (! c?$omron_fins_file_log )
        return;

    Log::write(OMRON_FINS::LOG_FILE_LOG, c$omron_fins_file_log);
}

# 
# A simple get_file_handle implementation taken from the main.zeek script
# generated using command:
#     zkg create --feature spicy-protocol-analyzer --packagedir my_protocol
#
function get_file_handle(c: connection, is_orig: bool): string {
    return cat(Analyzer::ANALYZER_OMRON_FINS_UDP, c$start_time, c$id, is_orig, c$orig);
}
