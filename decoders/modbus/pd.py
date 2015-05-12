## Modbus is a protocol where you have a client and one or more servers. This
## decoder is for Modbus RTU.
## The RX channel will be checked for both client->server and server->client
## communication, the TX channel only for client->server.

from math import ceil

import sigrokdecode as srd

RX = 0
TX = 1


class No_more_data(Exception):
    """ This exception is a signal that we should stop parsing an ADU as there
    is no more data to parse """
    pass


class Data:
    def __init__(self, start, end, data):
        self.start = start
        self.end = end
        self.data = data


class Modbus_ADU:
    """ An Application Data Unit is what MODBUS calls one message.
    Protocol decoders are supposed to keep track of state and then provide
    decoded data to the backend as it reads it. In modbus's case, the state is
    the ADU up to that point. This class represents the state and writes the
    messages to the backend.
    This class is for the common infrastructure between CS and SC"""

    def __init__(self, parent, start, write_channel, annotation_prefix):
        self.data = []
        self.parent = parent
        self.start = start
        self.last_read = start
        self.write_channel = write_channel
        self.last_byte_put = -1
        self.annotation_prefix = annotation_prefix
        # Any modbus message needs to be at least 4 long. The modbus function
        # may make this longer
        self.minimum_length = 4

        # This variable is used by an external function to determine when the
        # next frame should be started
        self.startNewFrame = False

    def add_data(self, start, end, data):
        ptype, rxtx, pdata = data
        self.last_read = end
        if ptype == 'DATA':
            self.data.append(Data(start, end, pdata[0]))
            self.parse()

    def put_if_needed(self, byte_to_put, annotation, message):
        """ This class keeps track of how much of the data has already been
        annotated. This function tells the parent class to write message, but
        only if it hasn't written about this bit before.
        byte_to_put: only write if it hasn't yet written byte_to_put. It will
           write from the start of self.last_byte_put+1 to the end of
           byte_to_put.
        annotation: annotation to write to, without annotation_prefix
        message: message to write"""
        if byte_to_put > len(self.data)-1:
            # if the byte_to_put hasn't been read yet
            raise No_more_data

        if byte_to_put > self.last_byte_put:
            self.parent.puta(
                self.data[self.last_byte_put+1].start,
                self.data[byte_to_put].end,
                self.annotation_prefix + annotation,
                message)
            self.last_byte_put = byte_to_put
            raise No_more_data

    def put_last_byte(self, annotation, message, maximum=None):
        """ Puts the last byte on the stack with message. The contents of the
        last byte will be applied to message using format. """
        last_byte_address = len(self.data) - 1
        if maximum is not None and last_byte_address > maximum:
            return
        self.put_if_needed(last_byte_address, annotation,
                           message.format(self.data[-1].data))

    def close(self, message_overflow):
        """ Function to be called when next message is started. As there is
        always space between one message and the next, we can use that space
        for errors at the end. """
        # TODO: figure out how to make this happen for last message
        data = self.data
        if len(data) < self.minimum_length:
            if len(data) == 0:
                # Sometimes happens with noise, safe to ignore
                return
            self.parent.puta(
                data[self.last_byte_put].end, message_overflow,
                self.annotation_prefix + "error",
                "Message too short or not finished")
        if len(data) > 256:
            try:
                self.put_if_needed(
                    len(data)-1,
                    self.annotation_prefix + "error",
                    "Modbus data frames are limited to 256 bytes")
            except No_more_data:
                pass

    def check_CRC(self, byte_to_put):
        """ Check the CRC code, data[byte_to_put] is the second byte of the CRC
        """
        # Check CRC
        crc_byte1, crc_byte2 = self.calc_crc(byte_to_put)
        data = self.data
        if data[-2].data == crc_byte1 and data[-1].data == crc_byte2:
            self.put_if_needed(byte_to_put, 'crc', "CRC correct")
        else:
            self.put_if_needed(
                byte_to_put, 'crc',
                "CRC should be {} {}".format(crc_byte1, crc_byte2))

    def half_word(self, start):
        """ Return the half word (16 bit) value starting at start bytes in. If
        it goes out of range it raises the usual errors. """
        if start+1 > len(self.data)-1:
            # If there isn't enough length to access data[start+1]
            raise No_more_data
        return self.data[start].data * 0x100 + self.data[start+1].data

    def calc_crc(self, last_byte):
        """ Calculate the CRC, as described in the spec
        The last byte of the crc should be data[last_byte] """
        if last_byte < 3:
            # every modbus ADU should be as least 4 long, so we should never
            # have to calculate a CRC on something shorter
            raise Exception("Could not calculate CRC: message too short")

        result = 0xFFFF
        magic_number = 0xA001  # as defined in the modbus specification
        for byte in self.data[:last_byte-1]:
            result = result ^ byte.data
            for i in range(8):
                LSB = result & 1
                result = result >> 1
                if (LSB):  # if the LSB is true
                    result = result ^ magic_number
        byte1 = result & 0xFF
        byte2 = (result & 0xFF00) >> 8
        return (byte1, byte2)

    def parse_write_single_coil(self):
        """ Parse function 5, write single coil """
        self.minimum_length = 8

        self.put_if_needed(1, "function",  "Function 5: Write Single Coil")

        address = self.half_word(2)
        self.put_if_needed(
            3, "address",
            "Address 0x{:X} / {:d}".format(address,
                                           address + 10000))

        raw_value = self.half_word(4)
        value = "Invalid Coil Value"
        if raw_value == 0x0000:
            value = "Coil Value OFF"
        elif raw_value == 0xFF00:
            value = "Coil Value ON"
        self.put_if_needed(5, 'data', value)

        self.check_CRC(7)

    def parse_write_single_register(self):
        """ Parse function 6, write single register """
        self.minimum_length = 8

        self.put_if_needed(1, "function",  "Function 6: Write Single Register")

        address = self.half_word(2)
        self.put_if_needed(
            3, "address",
            "Address 0x{:X} / {:d}".format(address,
                                           address + 30000))

        value = self.half_word(4)
        value_formatted = "Register Value 0x{0:X} / {0:d}".format(value)
        self.put_if_needed(5, 'data', value_formatted)

        self.check_CRC(7)

    def parse_diagnostics(self):
        """ Parse function 8, diagnostics. This function has many subfunctions,
        but they are all more or less the same """
        self.minimum_length = 8

        self.put_if_needed(1, "function", "Function 8: Diagnostics")

        diag_subfunction = {
            0: "Return Query data",
            1: "Restart Communications Option",
            2: "Return Diagnostics Register",
            3: "Change ASCII Input Delimiter",
            4: "Force Listen Only Mode",
            10: "Clear Counters and Diagnostic Register",
            11: "Return Bus Message Count",
            12: "Return Bus Communication Error Count",
            13: "Return Bus Exception Error Count",
            14: "Return Slave Message Count",
            15: "Return Slave No Response Count",
            16: "Return Slave NAK Count",
            17: "Return Slave Busy Count",
            18: "Return Bus Character Overrun Count",
            20: "Return Overrun Counter and Flag",
        }
        subfunction = self.half_word(2)
        subfunction_name = diag_subfunction.get(subfunction,
                                                "Reserved subfunction")
        self.put_if_needed(3, "data",
                           "Subfunction {}: {}".format(subfunction,
                                                       subfunction_name))

        diagnostic_data = self.half_word(4)
        self.put_if_needed(
            5, "data", "Data Field: {0} / 0x{0:04X}".format(diagnostic_data))

        self.check_CRC(7)

    def parse_mask_write_register(self):
        """ Parse function 22, Mask Write Register """
        self.minimum_length = 10
        data = self.data

        self.put_if_needed(1, "function", "Function 22: Mask Write Register")

        address = self.half_word(2)
        self.put_if_needed(
            3, "address",
            "Address 0x{:X} / {:d}".format(address, address + 30001))

        self.half_word(4)  # To make sure we don't oveflow data
        and_mask_1 = data[4].data
        and_mask_2 = data[5].data
        self.put_if_needed(5, "data",
                           "AND mask: {:08b} {:08b}".format(and_mask_1,
                                                            and_mask_2))

        self.half_word(6)  # To make sure we don't oveflow data
        or_mask_1 = data[6].data
        or_mask_2 = data[7].data
        self.put_if_needed(7, "data",
                           "OR mask: {:08b} {:08b}".format(or_mask_1,
                                                           or_mask_2))

        self.check_CRC(9)


class Modbus_ADU_SC(Modbus_ADU):
    """ SC stands for Server -> Client """
    def parse(self):
        data = self.data
        try:
            server_id = data[0].data
            if 1 <= server_id <= 247:
                message = "Slave ID: {}".format(server_id)
            else:
                message = "Slave ID {} is invalid"
            self.put_if_needed(0, "server-id", message)

            function = data[1].data
            if function == 1 or function == 2:
                self.parse_read_bits()
            elif function == 3 or function == 4 or function == 23:
                self.parse_read_registers()
            elif function == 5:
                self.parse_write_single_coil()
            elif function == 6:
                self.parse_write_single_register()
            elif function == 7:
                self.parse_read_exception_status()
            elif function == 8:
                self.parse_diagnostics()
            elif function == 11:
                self.parse_get_comm_event_counter()
            elif function == 12:
                self.parse_get_comm_event_log()
            elif function == 15 or function == 16:
                self.parse_write_multiple()
            elif function == 17:
                self.parse_report_server_id()
            elif function == 22:
                self.parse_mask_write_register()
            elif function > 0x80:
                self.parse_error()
            else:
                self.put_if_needed(1, "error",
                                   "Unknown function: {}".format(data[1].data))
                self.put_last_byte("error", "Unknown function")

            # if the message gets here without raising an exception, the
            # message goes on longer than it should

            self.put_last_byte("error", "Message too long")

        except No_more_data:
            # this is just a message saying we don't need to parse anymore this
            # round
            pass

    def parse_read_bits(self):
        self.mimumum_length = 5

        data = self.data
        function = data[1].data

        if function == 1:
            self.put_if_needed(1, "function",
                               "Function 1: Read Coils")
        else:
            self.put_if_needed(1, "function",
                               "Function 2: Read Discrete Inputs")

        bytecount = self.data[2].data
        self.minimum_length = 5 + bytecount  # 3 before data, 2 crc
        self.put_if_needed(2, "length",
                           "Byte count: {}".format(bytecount))

        # From here on out, we expect registers on 3 and 4, 5 and 6 etc
        # So registers never start when the length is even
        self.put_last_byte("data", "{:08b}", bytecount + 2)
        self.check_CRC(bytecount + 4)

    def parse_read_registers(self):
        self.mimumum_length = 5

        data = self.data

        function = data[1].data
        if function == 3:
            self.put_if_needed(1, "function",
                               "Function 3: Read Holding Registers")
        elif function == 4:
            self.put_if_needed(1, "function",
                               "Function 4: Read Input Registers")
        elif function == 23:
            self.put_if_needed(1, "function",
                               "Function 23: Read/Write Multiple Registers")

        bytecount = self.data[2].data
        self.minimum_length = 5 + bytecount  # 3 before data, 2 crc
        if bytecount % 2 == 0:
            self.put_if_needed(2, "length",
                               "Byte count: {}".format(bytecount))
        else:
            self.put_if_needed(
                2, "error",
                "Error: Odd byte count ({})".format(bytecount))

        # From here on out, we expect registers on 3 and 4, 5 and 6 etc
        # So registers never start when the length is even
        if len(data) % 2 == 1:
            register_value = self.half_word(-2)
            self.put_last_byte("data",
                               "0x{0:04X} / {0}".format(register_value),
                               bytecount + 2)
        else:
            raise No_more_data

        self.check_CRC(bytecount + 4)

    def parse_read_exception_status(self):
        self.mimumum_length = 5

        self.put_if_needed(1, "function",
                           "Function 7: Read Exception Status")
        exception_status = self.data[2].data
        self.put_if_needed(2, "data",
                           "Exception status: {:08b}".format(exception_status))
        self.check_CRC(4)

    def parse_get_comm_event_counter(self):
        self.mimumum_length = 8

        self.put_if_needed(1, "function",
                           "Function 11: Get Comm Event Counter")

        status = self.half_word(2)
        if status == 0x0000:
            self.put_if_needed(3, "data", "Status: not busy")
        elif status == 0xFFFF:
            self.put_if_needed(3, "data", "Status: busy")
        else:
            self.put_if_needed(3, "error",
                               "Bad status: 0x{:04X}".format(status))

        count = self.half_word(4)
        self.put_if_needed(5, "data",
                           "Event Count: {}".format(count))
        self.check_CRC(7)

    def parse_get_comm_event_log(self):
        self.mimumum_length = 11
        self.put_if_needed(1, "function",
                           "Function 12: Get Comm Event Log")

        data = self.data

        bytecount = data[2].data
        self.put_if_needed(2, "length", "Bytecount: {}".format(bytecount))
        # The bytecount is the length of everything except the slaveID,
        # function code, bytecount and CRC
        self.mimumum_length = 5 + bytecount

        status = self.half_word(3)
        if status == 0x0000:
            self.put_if_needed(4, "data", "Status: not busy")
        elif status == 0xFFFF:
            self.put_if_needed(4, "data", "Status: busy")
        else:
            self.put_if_needed(4, "error",
                               "Bad status: 0x{:04X}".format(status))

        event_count = self.half_word(5)
        self.put_if_needed(6, "data",
                           "Event Count: {}".format(event_count))

        message_count = self.half_word(7)
        self.put_if_needed(8, "data",
                           "Message Count: {}".format(message_count))

        self.put_last_byte("data", "Event: 0x{:02X}".format(data[-1].data),
                           bytecount + 2)

        self.check_CRC(bytecount + 4)

    def parse_write_multiple(self):
        """ Function 15 and 16 are almost the same, so we can parse them both
        using one function """
        self.mimumum_length = 8

        function = self.data[1].data
        if function == 15:
            data_unit = "Coils"
            max_outputs = 0x07B0
            long_address_offset = 10001
        elif function == 16:
            data_unit = "Registers"
            max_outputs = 0x007B
            long_address_offset = 30001

        self.put_if_needed(
            1, "function",
            "Function {}: Write Multiple {}".format(function, data_unit))

        starting_address = self.half_word(2)
        # Some instruction manuals use a long form name for addresses, this is
        # listed here for convienience.
        address_name = long_address_offset + starting_address
        self.put_if_needed(
            3, "address",
            "Start at address 0x{:X} / {:d}".format(starting_address,
                                                    address_name))

        quantity_of_outputs = self.half_word(4)
        if quantity_of_outputs <= max_outputs:
            self.put_if_needed(5, "data",
                               "Write {} {}".format(quantity_of_outputs,
                                                    data_unit))
        else:
            self.put_if_needed(
                5, "error",
                "Bad value: {} {}. Max is {}".format(quantity_of_outputs,
                                                     data_unit, max_outputs))

        self.check_CRC(7)

    def parse_report_server_id(self):
        # Buildup of this function:
        # 1 byte serverID
        # 1 byte function (17)
        # 1 byte bytecount
        # 1 byte serverID (counts for bytecount)
        # 1 byte Run Indicator Status (counts for bytecount)
        # bytecount - 2 bytes of device specific data (counts for bytecount)
        # 2 bytes of CRC
        self.mimumum_length = 7
        data = self.data
        self.put_if_needed(1, "function",
                           "Function 17: Report Server ID")

        bytecount = data[2].data
        self.put_if_needed(2, "length",
                           "Data is {} bytes long".format(bytecount))

        self.put_if_needed(3, "data", "serverID: {}".format(data[3].data))

        run_indicator_status = data[4].data
        if run_indicator_status == 0x00:
            self.put_if_needed(4, "data",
                               "Run Indicator status: Off")
        elif run_indicator_status == 0xFF:
            self.put_if_needed(4, "data",
                               "Run Indicator status: On")
        else:
            self.put_if_needed(
                4, "error",
                "Bad Run Indicator status: 0x{:X}".format(
                    run_indicator_status))

        self.put_last_byte(
            "data",
            "Device specific data: {}, '{}'".format(data[-1].data,
                                                    chr(data[-1].data)),
            2 + bytecount)

        self.check_CRC(4 + bytecount)

    def parse_error(self):
        self.mimumum_length = 5
        functioncode = self.data[1].data - 0x80

        functions = {
            1: "Read Coils",
            2: "Read Discrete Inputs",
            3: "Read Holding Registers",
            4: "Read Input Registers",
            5: "Write Single Coil",
            6: "Write Single Register",
            7: "Read Exception Status",
            8: "Diagnostic",
            11: "Get Com Event Counter",
            12: "Get Com Event Log",
            15: "Write Multiple Coils",
            16: "Write Multiple Registers",
            17: "Report Slave ID",
            20: "Read File Record",
            21: "Write File Record",
            22: "Mask Write Register",
            23: "Read/Write Multiple Registers",
            24: "Read FIFO Queue",
            43: "Read Device Identification/Encapsulated Interface Transport",
        }
        functionname = "{}: {}".format(
            functioncode,
            functions.get(functioncode, "Unknown function"))
        self.put_if_needed(1, "function",
                           "Error for function {}".format(functionname))

        error = self.data[2].data
        errorcodes = {
            1: "Illegal Function",
            2: "Illegal Data Address",
            3: "Illegal Data Value",
            4: "Slave Device Failure",
            5: "Acknowledge",
            6: "Slave Device Busy",
            8: "Memory Parity Error",
            10: "Gateway Path Unavailable",
            11: "Gateway Target Device failed to respond",
        }
        errorname = "{}: {}".format(error,
                                    errorcodes.get(error, "Unknown"))
        self.put_if_needed(2, "data", "Error {}".format(errorname))
        self.check_CRC(4)


class Modbus_ADU_CS(Modbus_ADU):
    """ CS stands for Client -> Server """
    def parse(self):
        data = self.data
        try:
            server_id = data[0].data
            message = ""
            if server_id == 0:
                message = "Broadcast message"
            elif 1 <= server_id <= 247:
                message = "Slave ID: {}".format(server_id)
            elif 248 <= server_id <= 255:
                message = "Slave ID: {} (reserved address)".format(server_id)
            self.put_if_needed(0, "server-id", message)

            function = data[1].data
            if function >= 1 and function <= 4:
                self.parse_read_data_command()
            if function == 5:
                self.parse_write_single_coil()
            if function == 6:
                self.parse_write_single_register()
            if function in {7, 11, 12, 17}:
                self.parse_single_byte_request()
            elif function == 8:
                self.parse_diagnostics()
            if function in {15, 16}:
                self.parse_write_multiple()
            elif function == 22:
                self.parse_mask_write_register()
            elif function == 23:
                self.parse_read_write_registers()
            else:
                self.put_if_needed(1, "error",
                                   "Unknown function: {}".format(data[1].data))
                self.put_last_byte("error", "Unknown function")

            # if the message gets here without raising an exception, the
            # message goes on longer than it should

            self.put_last_byte("error", "Message too long")

        except No_more_data:
            # this is just a message saying we don't need to parse anymore this
            # round
            pass

    def parse_read_data_command(self):
        """ Interpret a command to read x units of data starting at address, ie
        functions 1,2,3 and 4, and write the result to the annotations """
        data = self.data
        self.minimum_length = 8

        function = data[1].data
        functionname = {1: "Read Coils",
                        2: "Read Discrete Inputs",
                        3: "Read Holding Registers",
                        4: "Read Input Registers",
                        }[function]

        self.put_if_needed(1, "function",
                           "Function {}: {}".format(function, functionname))

        starting_address = self.half_word(2)
        # Some instruction manuals use a long form name for addresses, this is
        # listed here for convienience.
        # Example: holding register 60 becomes 30061.
        address_name = 10000 * function + 1 + starting_address
        self.put_if_needed(
            3, "address",
            "Start at address 0x{:X} / {:d}".format(starting_address,
                                                    address_name))

        self.put_if_needed(5, "length",
                           "Read {:d} units of data".format(self.half_word(4)))
        self.check_CRC(7)

    def parse_single_byte_request(self):
        """ Some MODBUS functions have no arguments, this parses those """
        function = self.data[1].data
        function_name = {7: "Read Exception Status",
                         11: "Get Comm Event Counter",
                         12: "Get Comm Event Log",
                         17: "Report Slave ID",
                         }[function]
        self.put_if_needed(1, "function",
                           "Function {}: {}".format(function, function_name))

        self.check_CRC(3)

    def parse_write_multiple(self):
        """ Function 15 and 16 are almost the same, so we can parse them both
        using one function """
        self.mimumum_length = 9

        function = self.data[1].data
        if function == 15:
            data_unit = "Coils"
            max_outputs = 0x07B0
            ratio_bytes_data = 1/8
            long_address_offset = 10001
        elif function == 16:
            data_unit = "Registers"
            max_outputs = 0x007B
            ratio_bytes_data = 2
            long_address_offset = 30001

        self.put_if_needed(
            1, "function",
            "Function {}: Write Multiple {}".format(function, data_unit))

        starting_address = self.half_word(2)
        # Some instruction manuals use a long form name for addresses, this is
        # listed here for convienience.
        address_name = long_address_offset + starting_address
        self.put_if_needed(
            3, "address",
            "Start at address 0x{:X} / {:d}".format(starting_address,
                                                    address_name))

        quantity_of_outputs = self.half_word(4)
        if quantity_of_outputs <= max_outputs:
            self.put_if_needed(5, "length",
                               "Write {} {}".format(quantity_of_outputs,
                                                    data_unit))
        else:
            self.put_if_needed(
                5, "error",
                "Bad value: {} {}. Max is {}".format(quantity_of_outputs,
                                                     data_unit, max_outputs))
        proper_bytecount = ceil(quantity_of_outputs * ratio_bytes_data)

        bytecount = self.data[6].data
        if bytecount == proper_bytecount:
            self.put_if_needed(6, "length", "Byte count: {}".format(bytecount))
        else:
            self.put_if_needed(
                6, "error",
                "Bad byte count, is {}, should be {}".format(bytecount,
                                                             proper_bytecount))
        self.mimumum_length = bytecount + 9

        self.put_last_byte("data", 'Value 0x{:X}', 6 + bytecount)

        self.check_CRC(bytecount + 8)

    def parse_read_file_record(self):
        self.put_if_needed(1, "function", "Function 20: Read file records")

        data = self.data

        bytecount = data[2].data
        self.minimum_length = 5 + bytecount
        # 1 for serverID, 1 for function, 1 for bytecount, 2 for CRC
        if 0x07 <= bytecount <= 0xF5:
            self.put_if_needed(2, "length",
                               "Request is {} bytes long".format(bytecount))
        else:
            self.put_if_needed(
                2, "error",
                "Request claims to be {} bytes long, legal values are between"
                " 7 and 247".format(bytecount))

        current_byte = len(data) - 1
        # Function 20 is a number of sub-requests, the first starting at 3,
        # the total length of the sub-requests is bytecount
        if current_byte <= bytecount + 2:
            step = (current_byte - 3) % 7
            if step == 0:
                if data[current_byte].data == 6:
                    self.put_if_needed(current_byte, "data",
                                       "Start sub-request")
                else:
                    self.put_if_needed(
                        current_byte, "error",
                        "First byte of subrequest should be 0x06")
            elif step == 1:
                raise No_more_data
            elif step == 2:
                file_number = self.half_word(current_byte - 1)
                self.put_if_needed(current_byte, "data",
                                   "Read File number {}".format(file_number))
            elif step == 3:
                raise No_more_data
            elif step == 4:
                record_number = self.half_word(current_byte - 1)
                self.put_if_needed(
                    current_byte, "address",
                    "Read from record number {}".format(record_number))
                # TODO: check if within range
            elif step == 5:
                raise No_more_data
            elif step == 6:
                records_to_read = self.half_word(current_byte - 1)
                self.put_if_needed(
                    current_byte, "length",
                    "Read {} records".format(records_to_read))
        self.check_CRC(4 + bytecount)

    def parse_read_write_registers(self):
        """ Parse function 23: Read/Write multiple registers """
        self.minimum_length = 13

        self.put_if_needed(1, "function",
                           "Function 23: Read/Write Multiple Registers")

        starting_address = self.half_word(2)
        # Some instruction manuals use a long form name for addresses, this is
        # listed here for convienience.
        # Example: holding register 60 becomes 30061.
        address_name = 30001 + starting_address
        self.put_if_needed(
            3, "address",
            "Read starting at address 0x{:X} / {:d}".format(starting_address,
                                                            address_name))

        self.put_if_needed(5, "length",
                           "Read {:d} units of data".format(self.half_word(4)))

        starting_address = self.half_word(6)
        self.put_if_needed(
            7, "address",
            "Write starting at address 0x{:X} / {:d}".format(starting_address,
                                                             address_name))

        quantity_of_outputs = self.half_word(8)
        self.put_if_needed(9, "length",
                           "Write {} registers".format(quantity_of_outputs))
        proper_bytecount = quantity_of_outputs * 2

        bytecount = self.data[10].data
        if bytecount == proper_bytecount:
            self.put_if_needed(10, "length",
                               "Byte count: {}".format(bytecount))
        else:
            self.put_if_needed(
                10, "error",
                "Bad byte count, is {}, should be {}".format(bytecount,
                                                             proper_bytecount))
        self.mimumum_length = bytecount + 13

        self.put_last_byte("data", 'Data, value 0x{:02X}', 10 + bytecount)

        self.check_CRC(bytecount + 12)


class Decoder(srd.Decoder):
    api_version = 2
    id = 'modbus'
    name = 'Modbus'
    longname = 'Modbus RTU over RS232/RS485'
    desc = 'Modbus RTU protocol for industrial applications'
    license = 'gplv2+'
    inputs = ['uart']
    outputs = ['modbus']
    annotations = (
        ('Sc-server-id', ''),
        ('Sc-function', ''),
        ('Sc-crc', ''),
        ('Sc-address', ''),
        ('Sc-data', ''),
        ('Sc-length', ''),
        ('Sc-error', ''),
        ('Cs-server-id', ''),
        ('Cs-function', ''),
        ('Cs-crc', ''),
        ('Cs-address', ''),
        ('Cs-data', ''),
        ('Cs-length', ''),
        ('Cs-error', ''),
    )
    annotation_rows = (
        ('sc', 'server->client', (0, 1, 2,  3,  4,  5, 6)),
        ('cs', 'client->server', (7, 8, 9, 10, 11, 12, 13)),
    )
    options = (
        dict(
            id="ScChannel",
            desc="Channel used for Server -> Client communication",
            default="RX",
            values=("RX", "TX")),
        )

    def __init__(self, **kwargs):
        self.ADUSc = None
        self.ADUCs = None

        self.bitlength = None

    def start(self):
        self.out_ann = self.register(srd.OUTPUT_ANN)

    def decode(self, ss, es, data):
        ptype, rxtx, pdata = data

        if rxtx == TX:
            self.decode_ADU(ss, es, data, "Cs")
        if rxtx == TX and self.options["ScChannel"] == "TX":
            self.decode_ADU(ss, es, data, "Sc")
        if rxtx == RX and self.options["ScChannel"] == "RX":
            self.decode_ADU(ss, es, data, "Sc")

    def puta(self, start, end, annotation_channel_text, message):
        """ Put an annotation from start to end, with annotation_channel as a
        string """
        annotation_channel = \
            [s[0] for s in self.annotations].index(annotation_channel_text)
        self.put(start, end, self.out_ann,
                 [annotation_channel, [message]])

    def decode_ADU(self, ss, es, data, direction):
        ptype, rxtx, pdata = data

        # We need to know how long bits are before we can start decoding
        # messages
        if self.bitlength is None:
            if ptype == "STARTBIT" or ptype == "STOPBIT":
                self.bitlength = es - ss
            else:
                return

        if direction == "Sc":
            if (self.ADUSc is None) or self.ADUSc.startNewFrame:
                self.ADUSc = Modbus_ADU_SC(self, ss, TX, "Sc-")
            ADU = self.ADUSc
        if direction == "Cs":
            if self.ADUCs is None or self.ADUCs.startNewFrame:
                self.ADUCs = Modbus_ADU_CS(self, ss, TX, "Cs-")
            ADU = self.ADUCs

        # According to the modbus spec, there should be 3.5 characters worth of
        # space between each message. But if within a message there is a length
        # of more than 1.5 character, that's an error. For our purposes
        # somewhere between seems fine.
        # A Character is 11 bits long, so (3.5 + 1.5)/2 * 11 ~= 28
        # TODO: display error for too short or too long
        if (ss - ADU.last_read) <= self.bitlength * 28:
            ADU.add_data(ss, es, data)
        else:
            # if there is any data in the ADU
            if len(ADU.data) > 0:
                # extend errors for 3 bits after last byte, we can guarentee
                # space
                ADU.close(ADU.data[-1].end + self.bitlength * 3)

            ADU.startNewFrame = True
            self.decode_ADU(ss, es, data, direction)
