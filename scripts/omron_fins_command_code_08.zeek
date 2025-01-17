module OMRON_FINS;

    function process_loop_back_test_detail(c: connection, finsCommand: OMRON_FINS::Command, link_id: string): string {
        # Local string to hold the response code for general logging
        local general_log_response_code : string;
        general_log_response_code = "";

        # Set sesssion detail log object
        c = set_session_detail_log(c);
        local info_detail_log = c$omron_fins_detail_log;

        info_detail_log$omron_fins_link_id = link_id;
        info_detail_log = process_command_and_datatype_detail(info_detail_log, finsCommand);

        if (finsCommand$icfDataType == OMRON_FINS_ENUMS::DataType_COMMAND) {
            info_detail_log$test_data = finsCommand$loopBackTestCommand$command$testData;
        } else if (finsCommand$icfDataType == OMRON_FINS_ENUMS::DataType_RESPONSE) {
            info_detail_log$response_code = OMRON_FINS_ENUMS::RESPONSE_CODE[finsCommand$loopBackTestCommand$response$responseCode];
            info_detail_log$test_data     = finsCommand$loopBackTestCommand$response$testData;

            # Set the general logging response code
            general_log_response_code = info_detail_log$response_code;
        }

        # Fire the event and tidy up
        OMRON_FINS::emit_omron_fins_detail_log(c);
        delete c$omron_fins_detail_log;

        # Return the response code for general logging
        return general_log_response_code;
    }

    function process_broadcast_test_results_read_detail(c: connection, finsCommand: OMRON_FINS::Command, link_id: string): string {
        # Local string to hold the response code for general logging
        local general_log_response_code : string;
        general_log_response_code = "";

        # Set sesssion detail log object
        c = set_session_detail_log(c);
        local info_detail_log = c$omron_fins_detail_log;

        info_detail_log$omron_fins_link_id = link_id;
        info_detail_log = process_command_and_datatype_detail(info_detail_log, finsCommand);

        # Note: For the Broadcast Test Results Read command,there is no data to process; therefore we only process the response

        if (finsCommand$icfDataType == OMRON_FINS_ENUMS::DataType_RESPONSE) {
            info_detail_log$response_code = OMRON_FINS_ENUMS::RESPONSE_CODE[finsCommand$broadcastTestResultsReadCommand$response$responseCode];
            info_detail_log$number_of_receptions = finsCommand$broadcastTestResultsReadCommand$response$numberOfReceptions;

            # Set the general logging response code
            general_log_response_code = info_detail_log$response_code;

            # Fire the event and tidy up
            OMRON_FINS::emit_omron_fins_detail_log(c);
            delete c$omron_fins_detail_log;
        }

        # Return the response code for general logging
        return general_log_response_code;
    }

    function process_broadcast_test_data_send_detail(c: connection, finsCommand: OMRON_FINS::Command, link_id: string) {
        c = set_session_detail_log(c);

        local info_detail_log = c$omron_fins_detail_log;
        info_detail_log$omron_fins_link_id = link_id;
        info_detail_log = process_command_and_datatype_detail(info_detail_log, finsCommand);

        if (finsCommand$icfDataType == OMRON_FINS_ENUMS::DataType_COMMAND) {
            info_detail_log$test_data     = finsCommand$broadcastTestDataSendCommand$command$testData;

            # Fire the event and tidy up
            OMRON_FINS::emit_omron_fins_detail_log(c);
            delete c$omron_fins_detail_log;
        }
        
        # Note: No response is returned from the Broadcast Test Data Send command.
    }
