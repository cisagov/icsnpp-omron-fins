spicy_add_analyzer(
    NAME omron_fins
    PACKAGE_NAME omron_fins
    SOURCES zeek_omron_fins.spicy  
            omron_fins_functions.spicy  
            omron_fins_functions.cc  
            omron_fins.spicy  
            omron_fins.evt  
            omron_fins_enums.spicy  
            omron_fins_error_codes.spicy  
            omron_fins_command_code_01.spicy  
            omron_fins_command_code_02.spicy  
            omron_fins_command_code_03.spicy  
            omron_fins_command_code_04.spicy  
            omron_fins_command_code_05.spicy  
            omron_fins_command_code_06.spicy  
            omron_fins_command_code_07.spicy  
            omron_fins_command_code_08.spicy  
            omron_fins_command_code_09.spicy
            omron_fins_command_code_0C.spicy
            omron_fins_command_code_21.spicy
            omron_fins_command_code_22.spicy
            omron_fins_command_code_23.spicy
            omron_fins_command_code_26.spicy
    SCRIPTS __load__.zeek 
            main.zeek 
            omron_fins_enums.zeek 
            omron_fins_error_codes.zeek
            omron_fins_processing.zeek 
            omron_fins_event_processing.zeek 
            omron_fins_types.zeek 
            omron_fins_utilities.zeek 
            omron_fins_command_code_01.zeek 
            omron_fins_command_code_02.zeek 
            omron_fins_command_code_03.zeek 
            omron_fins_command_code_04.zeek 
            omron_fins_command_code_05.zeek 
            omron_fins_command_code_06.zeek 
            omron_fins_command_code_07.zeek  
            omron_fins_command_code_08.zeek  
            omron_fins_command_code_09.zeek
            omron_fins_command_code_0C.zeek
            omron_fins_command_code_21.zeek
            omron_fins_command_code_22.zeek
            omron_fins_command_code_23.zeek
            omron_fins_command_code_26.zeek
)