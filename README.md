# Build Status

| Source       | `main` Status | `main` Timestamp |
|--------------|--------------|------------|
| **CISAGOV** | ![Build Status](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.github.com%2Frepos%2Fcisagov%2Ficsnpp-omron-fins%2Fcommits%2Fmain%2Fstatus&query=state&label=build) | ![Last Build](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.github.com%2Frepos%2Fcisagov%2Ficsnpp-omron-fins%2Fcommits%2Fmain%2Fstatus&query=statuses[0].updated_at&label=last%20build&color=lightgrey) |
| **Development** | ![Build Status](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.github.com%2Frepos%2Fparsitects%2Ficsnpp-omron-fins%2Fcommits%2Fmain%2Fstatus&query=state&label=build) | ![Last Build](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.github.com%2Frepos%2Fparsitects%2Ficsnpp-omron-fins%2Fcommits%2Fmain%2Fstatus&query=statuses[0].updated_at&label=last%20build&color=lightgrey) |

# ICSNPP-OMRON-FINS
Industrial Control Systems Network Protocol Parsers (ICSNPP) - Omron FINS (Factory Interface Network Service) over TCP and UDP

## Overview
ICSNPP-Omron-FINS is a Spicy based Zeek plugin for parsing and logging fields within the Omron FINS protocol.

Omron FINS is a protocol created by Omron Corporation for commuincation between Omron programamable logic controllers (PLCs), human-machine interfaces (HMIs), and other devices in industrial automation systems.  It is widely used in manufacturing, process control, and other industrial applications.

The FINS protocol can be addressed to Omron CV-Series PCs (programmable controllers), C-Series PCS, SYSMAC NET Link Units, SYSMAC LINK Support Boards, and CPU Bus Units, such as Personal Computer Units and BASIC Units.

This parser targets the FINS commands available to the CV-Series, C-Series, SYSMAC LINK, and SYSMAC NET PCs transported over TCP and UDP.

## Installation (via zkg)

### Package Manager

This script is available as a package for [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html). Zeek includes Spicy support by default as of [v6.0.0](https://github.com/zeek/zeek/releases/tag/v6.0.0).

```bash
$ zkg refresh
$ zkg install icsnpp-omron-fins
```

If this package is installed from ZKG, it will be added to the available plugins. This can be tested by running `zeek -NN`. If installed correctly, users will see `ANALYZER_OMRON_FINS` under the list of `Zeek::Spicy` analyzers.

If users have ZKG configured to load packages (see `@load packages` in the( [ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)), this plugin and these scripts will automatically be loaded and ready to go.)

If users are compiling the code manually, use clang as the compiler by compiling zeek with clang. Installing the package with zkg is not impacted.

## Installation (via git clone)

```bash
git clone https://github.com/cisagov/icsnpp-omron-fins.git
cd icsnpp-omron-fins
mkdir build && cd build && cmake .. && make && cd ..
```

From here you can install the locally built files through `zkg install ./icsnpp-omron-fins` and run it like you would normally.
Or you can manually run the parser without installing it: `zeek ./build/omron_fins.hlto ./scripts/__load__.zeek  -Cr <pcap>`

## Protocol Detection and Custom Ports

The parser uses port-based detection for both TCP and UDP. The TCP parser validates the `FINS` header after Zeek assigns the connection to the analyzer, but that validation does not activate the analyzer on an otherwise unconfigured port.

To add ports through the environment, provide comma-separated Zeek ports, including each transport suffix:

```bash
export ZEEK_OMRON_FINS_PORTS=12345/tcp,12345/udp
```

Alternatively, add TCP and UDP ports to their respective exported sets in Zeek site policy:

```zeek
redef OMRON_FINS::omron_fins_ports_tcp += { 12345/tcp };
redef OMRON_FINS::omron_fins_ports_udp += { 12345/udp };
```

Configure only the transports that carry FINS at your site. The parser adds the final contents of both sets to `likely_server_ports` for direction inference and registers each set with its transport-specific analyzer. Adding a port only to `likely_server_ports` does not enable parsing; analyzer registration is required.

Environment and site-policy changes are read when Zeek starts, so restart or redeploy the affected Zeek processes after changing them. Port configuration alone does not require rebuilding the Spicy analyzer. If you edit an installed package's source instead, reinstall or redeploy the package so the updated script reaches every sensor.

Port registration sends all traffic using a configured server port directly to the corresponding FINS analyzer. Assign only ports dedicated to FINS: unrelated or mixed-protocol traffic can cause parser violations, misleading logs, and unnecessary processing.


## Logging Capabilities

### OMRON FINS Log (omron_fins_general.log)

#### Overview

This log summarizes the header data used for FINS commands and responses.

#### Fields Captured
| Field                       | Type            | Description                                                                               |
| ----------------------------|-----------------|-------------------------------------------------------------------------------|
| ts                          | time            | Timestamp (network time)                                                      |
| uid                         | string          | Unique ID for this connection                                                 |
| id                          | conn_id         | Default Zeek connection info (IP Addresses, Ports, etc.)                      |
| proto                       | string          | Transport protocol                                                            |
| omron_fins_link_id          | string          | Link id to link one log file to another                                       |
| tcp_header                  | string          | ASCII code: 'FINS'                                                            |
| tcp_length                  | count           | Length of data from command onwards                                           |
| tcp_command                 | string          | TCP Command - e.g. Frame Send, FINS Node Address Send, etc.                   |
| tcp_error_code              | string          | TCP error code                                                                |
| client_node_address         | count           | FINS node address of FINS/TCP client. 1 to 254                                |
| server_node_address         | count           | FINS node address of FINS/TCP server. 1 to 254                                |
| icf_gateway                 | string          | Gateway usage (0 don't use; 1 use); per the protocol specification, set to 1. |
| icf_data_type               | string          | Data type (0: command; 1: response)                                           |
| icf_response_setting        | string          | Response setting (0: response required; 1: response not required)             |
| gateway_count               | count           | Gateway Count.  Per the protocol specification, set to 02                     |
| destination_network_address | count           | Destination network address                                                   |
| destination_node_number     | count           | Destination node number                                                       |
| destination_unit_address    | count           | Destination unit address                                                      |
| source_network_address      | count           | Source network address                                                        |
| source_node_number          | count           | Source node number                                                            |
| source_unit_address         | count           | Source unit address                                                           |
| service_id                  | string          | Service ID.  Used to identify the processing generating the transmission      |
| command_code                | string          | The command to execute                                                        |
| response_code               | string          | The response from executing the command                                       |

### OMRON FINS Detail Log (omron_fins_detail.log)

#### Overview

This log captures the detailed data used with the FINS commands and responses.

#### Fields Captured
| Field                              | Type             | Description                                                                                                                                         |
| -----------------------------------|------------------|---------------------------------------------------------------------------------------------------------------------------------------------------- |
| ts                                 | time             | Timestamp (network time)                                                                                                                            |
| uid                                | string           | Unique ID for this connection                                                                                                                       |
| id                                 | conn_id          | Default Zeek connection info (IP Addresses, Ports, etc.)                                                                                            |
| omron_fins_link_id                 | string           | Link id to link one log file to another                                                                                                             |
| command_code                       | string           | The command to execute                                                                                                                              |
| icf_data_type                      | string           | Data type (0: command; 1: response)                                                                                                                 |
| memory_area_code                   | string           | The data area to read/write                                                                                                                         |
| beginning_address                  | string           | The address of the first word/bit/flag to read/write                                                                                                |
| number_of_items                    | count            | The number of items to read/write                                                                                                                   |
| parameter_area_code                | string           | The parameter area to read/write                                                                                                                    |
| beginning_word                     | string           | The first word to read/write                                                                                                                        |
| number_of_words                    | count            | The number of words to read/write                                                                                                                   |
| last_word_bit                      | count            | Last word bit (0: OFF; 1: ON)                                                                                                                       |
| response_code                      | string           | The response from executing the command                                                                                                             |
| data                               | string           | The data to be read/written                                                                                                                         |
| year                               | count            | Clock read/write: Year                                                                                                                              |
| month                              | count            | Clock read/write: Month                                                                                                                             |
| date                               | count            | Clock read/write: Date                                                                                                                              |
| hour                               | count            | Clock read/write: Hour                                                                                                                              |
| minute                             | count            | Clock read/write: Minute                                                                                                                            |
| second                             | count            | Clock read/write: Second                                                                                                                            |
| day                                | string           | Clock read/write: Day                                                                                                                               |
| clock_time                         | time             | Clock read/write: Calculated clock time                                                                                                             |
| intelligent_id_no                  | string           | Data Link Table Read/Write - designate S (53) and N (4E) in ASCII.                                                                                  |
| first_word                         | string           | Data Link Table Read/Write - per the protocol specification, set to 0000                                                                            |
| read_length                        | string           | Data Link Table Read - regardless of the value set, the data link tables for the number of link nodes that has been set will be read.               |
| data_length                        | string           | The number of bytes to read/write/transfer/compare                                                                                                  |
| num_of_link_nodes                  | count            | Data Link Table Read/Write - the number of link nodes                                                                                               |
| block_record_data_link_status      | string           | Data Link Table Read - data Link Status (0: normal; 1: warning)                                                                                     |
| block_record_num_of_link_nodes     | count            | Data Link Table Read - number of link nodes                                                                                                         |
| block_record_node_num              | count            | Data Link Table Write - the data link node number                                                                                                   |
| block_record_cio_area_first_word   | string           | Data Link Table Read/Write - the first word in a data link in the CIO Area                                                                          |
| block_record_kind_of_dm            | string           | Data Link Table Read/Write - kind of DM; Per the protocol specification, set to 00.                                                                 |
| block_record_dm_area_first_word    | string           | Data Link Table Read/Write - the first word in a data link in the DM Area                                                                           |
| block_record_num_of_total_words    | count            | Data Link Table Read/Write - the total number of words used for data links in the CIO and DM Area                                                   |
| program_no                         | count            | Per the protocol specification, set to 0000                                                                                                         |
| protect_code                       | count            | Per the protocol specification, set to 00                                                                                                           |
| password                           | string           | Program Area Protect/Clear - password                                                                                                               |
| last_word                          | string           | Program Area Protect/Clear - per the protocol specification, set to 00000000                                                                        |
| clear_code                         | string           | Program Area Clear - per the protocol specification, set to 00                                                                                      |
| number_of_bytes                    | count            | The number of data bytes                                                                                                                            |
| run_mode                           | string           | Run mode (00: Program; 01: Debug; 02: Monitor; 04: Run)                                                                                             |
| controller_data_to_read            | string           | Controller Data Read - the specified data to read                                                                                                   |
| controller_model                   | string           | Controller Data Read - model                                                                                                                        |
| controller_version                 | string           | Controller Data Read - version                                                                                                                      |
| for_system_use                     | string           | Controller Data Read - reserved for system use                                                                                                      |
| program_area_size                  | count            | Controller Data Read - the size of PC Setup and program area                                                                                        |
| iom_size                           | count            | Controller Data Read - the size of the area in which bit/word commands can be used                                                                  |
| no_of_dm_words                     | count            | Controller Data Read - total words in the DM area                                                                                                   |
| timer_size                         | count            | Controller Data Read - maxium no. of timers/counters available                                                                                      |
| expansion_dm_size                  | count            | Controller Data Read - banks in the expansion DM area                                                                                               |
| no_of_steps_transitions            | count            | Controller Data Read - maximum no. of steps/transitions available                                                                                   |
| kind_of_memory_card                | string           | Controller Data Read - kind of memory card (00: No memory card; 01: SPRAM; 02: EPROM; 03: EEPROM)                                                   |
| memory_card_size                   | count            | Controller Data Read - size of the memory card. K byte (1 word - 2 bytes)                                                                           |
| cpu_bus_unit_config                | vector of count  | Controller Data Read - CPU Bus unit numbers                                                                                                         |
| no_of_sysmac_bus_master_mounted    | count            | Controller Data Read - no of SYSMAC BUS Masters mounted                                                                                             |
| no_of_sysmac_bus2_master_mounted   | count            | Controller Data Read - no of SYSMAC BUS Masters mounted                                                                                             |
| peripheral_device_connected        | count            | Controller Data Read - peripheral device connected (0: no; 1: yes)                                                                                  |
| built_in_host_interface            | count            | Controller Data Read - with built-in host insterface (always 1)                                                                                     |
| no_of_racks_connected              | count            | Controller Data Read - no of Racks connected to the PC                                                                                              |
| no_of_units                        | count            | The number of data units read/returned                                                                                                              |
| unit_address                       | string           | Connection Data Read - the unit address of the first Unit whos model number is to be read.                                                          |
| model_number                       | string           | Connection Data Read - the model number read                                                                                                        |
| controller_status_data_read_status | string           | Controller Status Read - the operating status of the PC (00: Stop; 01: Run; 80: Standby)                                                            |
| controller_status_data_read_mode   | string           | Controller Status Read - PC mode (00: PROGRAM; 01: DEBUG; 02: MONITOR; 04: RUN)                                                                     |
| fatal_error                        | vector of string | Controller Status Read - the contents of PC fatal error information                                                                                 |
| non_fatal_error                    | vector of string | Controller Status Read - the contents of PC non-fatal error information                                                                             |
| message_yes_no                     | vector of string | Controller Status Read - corresponding message numbers (0: No; 1: Yes)                                                                              |
| fal_fals_no                        | count            | Controller Status Read - the highest priority FALS or FALS error.                                                                                   |
| error_message                      | string           | Controller Status Read - the Error message of the present FAL/FALS number                                                                           |
| cycle_time_read_parameter          | string           | Cycle Time Read - parameter code (00: Initialized the cycle time; 01: Read the average, max, and min cycletime)                                     |
| average_cycle_time                 | double           | Cycle Time Read - average cycle time (max cycle time + min cycle time) / 2                                                                          |
| max_cycle_time                     | double           | Cycle Time Read - maximum cycle time                                                                                                                |
| min_cycle_time                     | double           | Cycle Time Read - minimum cycle time                                                                                                                |
| test_data                          | string           | Loop-Back Test - test data to be transmitted                                                                                                        |
| number_of_receptions               | count            | Broadcast Test Results Read - The number of times the Broadcast Test Data Send command has been executed since the last Broadcast Test Results Read |
| command                            | string           | Message Read / Message Clear / FAL/FALS Read - the actual command (READ, CLEAR, FAL/FALS)                                                           |
| message_no_0                       | string           | Message Read / Message Clear - message 0 enabled (True/False)                                                                                       |
| message_no_1                       | string           | Message Read / Message Clear - message 1 enabled (True/False)                                                                                       |
| message_no_2                       | string           | Message Read / Message Clear - message 2 enabled (True/False)                                                                                       |
| message_no_3                       | string           | Message Read / Message Clear - message 3 enabled (True/False)                                                                                       |
| message_no_4                       | string           | Message Read / Message Clear - message 4 enabled (True/False)                                                                                       |
| message_no_5                       | string           | Message Read / Message Clear - message 5 enabled (True/False)                                                                                       |
| message_no_6                       | string           | Message Read / Message Clear - message 6 enabled (True/False)                                                                                       |
| message_no_7                       | string           | Message Read / Message Clear - message 7 enabled (True/False)                                                                                       |
| message_0                          | string           | Message Read - message 0 data                                                                                                                       |
| message_1                          | string           | Message Read - message 1 data                                                                                                                       |
| message_2                          | string           | Message Read - message 2 data                                                                                                                       |
| message_3                          | string           | Message Read - message 3 data                                                                                                                       |
| message_4                          | string           | Message Read - message 4 data                                                                                                                       |
| message_5                          | string           | Message Read - message 5 data                                                                                                                       |
| message_6                          | string           | Message Read - message 6 data                                                                                                                       |
| message_7                          | string           | Message Read - message 7 data                                                                                                                       |
| fal_fals_no_0                      | string           | Message FAL/FALS - FAL/FALS 0 enabled (True/False)                                                                                                  |
| fal_fals_no_1                      | string           | Message FAL/FALS - FAL/FALS 1 enabled (True/False)                                                                                                  |
| fal_fals_no_2                      | string           | Message FAL/FALS - FAL/FALS 2 enabled (True/False)                                                                                                  |
| fal_fals_no_3                      | string           | Message FAL/FALS - FAL/FALS 3 enabled (True/False)                                                                                                  |
| fal_fals_no_4                      | string           | Message FAL/FALS - FAL/FALS 4 enabled (True/False)                                                                                                  |
| fal_fals_no_5                      | string           | Message FAL/FALS - FAL/FALS 5 enabled (True/False)                                                                                                  |
| fal_fals_no_6                      | string           | Message FAL/FALS - FAL/FALS 6 enabled (True/False)                                                                                                  |
| fal_fals_no_7                      | string           | Message FAL/FALS - FAL/FALS 7 enabled (True/False)                                                                                                  |
| fal_fals_no_8                      | string           | Message FAL/FALS - FAL/FALS 8 enabled (True/False)                                                                                                  |
| fal_fals_no_9                      | string           | Message FAL/FALS - FAL/FALS 9 enabled (True/False)                                                                                                  |
| fal_fals_no_10                     | string           | Message FAL/FALS - FAL/FALS 10 enabled (True/False)                                                                                                 |
| fal_fals_no_11                     | string           | Message FAL/FALS - FAL/FALS 11 enabled (True/False)                                                                                                 |
| fal_fals_no_12                     | string           | Message FAL/FALS - FAL/FALS 12 enabled (True/False)                                                                                                 |
| fal_fals_no_13                     | string           | Message FAL/FALS - FAL/FALS 13 enabled (True/False)                                                                                                 |
| fal_fals_0                         | string           | Message FAL/FALS - error message 0                                                                                                                  |
| fal_fals_1                         | string           | Message FAL/FALS - error message 1                                                                                                                  |
| fal_fals_2                         | string           | Message FAL/FALS - error message 2                                                                                                                  |
| fal_fals_3                         | string           | Message FAL/FALS - error message 3                                                                                                                  |
| fal_fals_4                         | string           | Message FAL/FALS - error message 4                                                                                                                  |
| fal_fals_5                         | string           | Message FAL/FALS - error message 5                                                                                                                  |
| fal_fals_6                         | string           | Message FAL/FALS - error message 6                                                                                                                  |
| fal_fals_7                         | string           | Message FAL/FALS - error message 7                                                                                                                  |
| fal_fals_8                         | string           | Message FAL/FALS - error message 8                                                                                                                  |
| fal_fals_9                         | string           | Message FAL/FALS - error message 9                                                                                                                  |
| fal_fals_10                        | string           | Message FAL/FALS - error message 10                                                                                                                 |
| fal_fals_11                        | string           | Message FAL/FALS - error message 11                                                                                                                 |
| fal_fals_12                        | string           | Message FAL/FALS - error message 12                                                                                                                 |
| fal_fals_13                        | string           | Message FAL/FALS - error message 13                                                                                                                 |
| acquire_network_address            | count            | Access Right Acquire - network address of device with access right                                                                                  |
| acquire_node_number                | count            | Access Right Acquire - node number of device with access right                                                                                      |
| acquire_unit_address               | count            | Access Right Acquire - unit address of Unit with access right                                                                                       |
| no_of_bits                         | count            | Forces Set/Reset - the number of bits/flags to be controlled                                                                                        |
| set_reset_specification            | string           | Forces Set/Reset - the action to be taken for each bit/flag                                                                                         |
| bit_flag                           | count            | Forces Set/Reset - the bit or flag to be controlled                                                                                                 |

## OMRON FINS Error Log (omron_fins_error.log)

#### Overview

This log captures the error data used with the FINS commands and responses.

#### Fields Captured
| Field                              | Type             | Description                                                                                                                                         |
| -----------------------------------|------------------|-------------------------------------------------------------------- |
| ts                                 | time             | Timestamp (network time)                                            |
| uid                                | string           | Unique ID for this connection                                       |
| id                                 | conn_id          | Default Zeek connection info (IP Addresses, Ports, etc.)            |
| omron_fins_link_id                 | string           | Link id to link one log file to another                             |
| command_code                       | string           | The command to execute                                              |
| icf_data_type                      | string           | Data type (0: command; 1: response)                                 |
| response_code                      | string           | The response from executing the command                             |
| error_reset_fal_no                 | string           | Error Clear - the code of the error to be reset.                    |
| beginning_record_no                | count            | Error Log Read - the first record to be read                        |
| max_no_stored_records              | count            | Error Log Read - the maximum number of records that can be recorded |
| no_of_stored_records               | count            | Error Log Read - the number of records that have been recorded      |
| no_of_records                      | count            | Error Log Read - the number of records read                         |
| error_code_1                       | string           | Error Log Read - associated error code                              |
| error_code_2                       | string           | Error Log Read - associated error code                              |
| minute                             | count            | Error Log Read - minute error occurred                              |
| second                             | count            | Error Log Read - second error occurred                              |
| day                                | count            | Error Log Read - day error occurred                                 |
| hour                               | count            | Error Log Read - hour error occurred                                |
| year                               | count            | Error Log Read - year error occurred                                |
| month                              | count            | Error Log Read - month error occurred                               |

## OMRON FINS Data Link Status Read Log (omron_fins_data_link_status_read.log)

#### Overview

This log captures the information associated with the Data Link Status Read command

#### Fields Captured
| Field                              | Type             | Description                                                                                                                                         |
| -----------------------------------|------------------|----------------------------------------------------------------------|
| ts                                 | time             | Timestamp (network time)                                             |
| uid                                | string           | Unique ID for this connection                                        |
| id                                 | conn_id          | Default Zeek connection info (IP Addresses, Ports, etc.)             |
| omron_fins_link_id                 | string           | Link id to link one log file to another                              |
| command_code                       | string           | The command to execute                                               |
| icf_data_type                      | string           | Data type (0: command; 1: response)                                  |
| response_code                      | string           | The response from executing the command                              |
| node_number                        | count            | Node number                                                          |
| data_links                         | string           | Data links (0: Not active; 1: Active)                                |
| node_setting                       | string           | Slave/Master (0: Slave; 1: Master)                                   |
| master_node_number                 | count            | The node number of the master node of the data link will be returned |
| error_status                       | string           | Error status (0: Normal; 1: Error)                                   |
| mode_status                        | string           | Mode status (0: Stop; 1: Run)                                        |
| warning_status                     | string           | Warning status (0: Normal; 1: Warning)                               |

## OMRON FINS Network Status Read Log (omron_fins_network_status_read.log)

#### Overview

This log captures the information associated with the Network Status Read command.

#### Fields Captured
| Field                              | Type             | Description                                                                                                                                         |
| -----------------------------------|------------------|---------------------------------------------------------------------------------------------|
| ts                                 | time             | Timestamp (network time)                                                                    |
| uid                                | string           | Unique ID for this connection                                                               |
| id                                 | conn_id          | Default Zeek connection info (IP Addresses, Ports, etc.)                                    |
| omron_fins_link_id                 | string           | Link id to link one log file to another                                                     |
| command_code                       | string           | The command to execute                                                                      |
| icf_data_type                      | string           | Data type (0: command; 1: response)                                                         |
| response_code                      | string           | The response from executing the command                                                     |
| node_number                        | count            | Node number                                                                                 |
| in_network                         | string           | In Network (1: In Network; 0 Not in network)                                                |
| exit_status                        | string           | Exit status (1: Exited because of an error; 0: Normal exit)                                 |
| polling                            | string           | Polling (1: Unit does not respond to polling)                                               |
| communication_cycle_time           | double           | The actual communications cycle time                                                        |
| current_polling_node_number        | count            | The node number of the unit that is the polling point                                       |
| cyclic_operation                   | string           | Indicates the current status of cyclic operation (00: Stopped; 01: Active)                  |
| cyclic_transmission_status         | string           | Indicates the current status of cyclic transmission (00: No transmission; 01: Transmission) |
| non_fatal_error                    | string           | Indicates nodes in which non-fatal errors occurred in cyclic transmission                   |
| cyclic_error_count                 | count            | Indicates how many cyclic errors occurred since start up.                                   |

## OMRON FINS Network Status Read Log (omron_fins_file.log)

#### Overview

This log captures the fields associated with the File, Memory, and Volume information

#### Fields Captured
| Field                              | Type             | Description                                                                                                                                         |
| -----------------------------------|------------------|------------------------------------------------------------------------------------|
| ts                                 | time             | Timestamp (network time)                                                           |
| uid                                | string           | Unique ID for this connection                                                      |
| id                                 | conn_id          | Default Zeek connection info (IP Addresses, Ports, etc.)                           |
| omron_fins_link_id                 | string           | Link id to link one log file to another                                            |
| command_code                       | string           | The command to execute                                                             |
| icf_data_type                      | string           | Data type (0: command; 1: response)                                                |
| response_code                      | string           | The response from executing the command                                            |
| disk_no                            | count            | Disk No.                                                                           |
| beginning_file_position            | string           | The first file to be read                                                          |
| no_of_files                        | count            | The number of files.                                                               |
| volume_label                       | string           | The volume label                                                                   |
| year                               | count            | The year the volume label or file was created                                      |
| month                              | count            | The month the volume label or file was created                                     |
| day                                | count            | The day the volume label or file was created                                       |
| hour                               | count            | The hour the volume label or file was created                                      |
| minute                             | count            | The minute the volume label or file was created                                    |
| second                             | count            | The second the volume label or file was created                                    |
| total_capacity                     | count            | The total capacity of the file device                                              |
| unused_capacity                    | count            | The number of bytes still available                                                |
| total_no_files                     | count            | The number of files recorded in the file device                                    |
| no_files_read                      | count            | The number of files that have been read.                                           |
| last_file                          | count            | Last file (0:Without last file; 1: With last file)                                 |
| file_name                          | string           | The name of the file                                                               |
| file_capacity                      | count            | The capacity (bytes) of the file                                                   |
| file_position                      | count            | The number of bytes fron the start of the file from which to start reading/writing |
| data_length                        | count            | The number of bytes of data to read/write                                          |
| fuid                               | string           | File unique identifier                                                             |
| parameter_code                     | string           | Parameter code                                                                     |
| src_disk_no                        | count            | Disk number for the source file                                                    |
| src_file_name                      | string           | File name for the source file                                                      |
| dst_disk_no                        | count            | Disk number for the destination file                                               |
| dst_file_name                      | string           | File name for the destination file                                                 |
| old_file_name                      | string           | The original file name                                                             |
| new_file_name                      | string           | The new file name                                                                  |
| parameter_area_code                | string           | The parameter area to be used for data transfer/comparison                         |
| beginning_address                  | string           | The first word in the parameter area to be transferred/compared                    |
| no_of_words                        | count            | The number of data words to be transferred/compared                                |
| memory_area_code                   | string           | The memory area to be used for data transfer                                        |
| no_of_items                        | count            | The number of items to be transferred/compared                                     |
| program_no                         | string           | Program number                                                                     |
| no_of_bytes                        | count            | The number of data bytes to be transferred/compared                                |
| beginning_word                     | string           | Beginning word                                                                     |
| beginning_block_no                 | count            | The first block                                                                    |
| no_of_blocks                       | count            | The total number of blocks to be read                                              |
| remaining_blocks                   | count            | The number of blocks not to be read                                                |
| total_no_of_blocks                 | count            | The total number of blocks in File Memory                                         |
| memory_type                        | string           | The type of File Memory being used                                                 |
| data_type                          | string           | Date type (000: Empty; 001: I/O data; 010: User program; 011: Comments)            |
| last_block                         | string           | The last block                                                                     |
| protected                          | string           | Protected                                                                          |
| control_data                       | count            | The number of comments.  Used for commend data only                                |
| block_no                           | count            | The number of the File Memory block to read                                        |
| memory_data                        | string           | The File Memory data to be read/written                                            |
