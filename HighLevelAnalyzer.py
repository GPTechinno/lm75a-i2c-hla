# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, NumberSetting

regs = {
    0: "Temperature",
    1: "Configuration",
    2: "Thyst",
    3: "Tos",
    7: "ProductID",
}

def get_reg_name(reg_addr: int) -> str:
    """Get the register name by address."""
    try:
        return regs[reg_addr]
    except KeyError:
        return f"0x{reg_addr:02X}"

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    """LM75a I2C protocol decoder High Level Analyzer."""
    result_types = {
        'read_register': {
            'format': 'i2c@{{data.i2c_addr}} Read {{data.reg_name}}={{data.value}}'
        },
        'read_register_temp': {
            'format': 'i2c@{{data.i2c_addr}} Read {{data.reg_name}} {{data.value}}°C'
        },
        'write_register': {
            'format': 'i2c@{{data.i2c_addr}} Write {{data.reg_name}}={{data.value}}'
        },
        'write_register_temp': {
            'format': 'i2c@{{data.i2c_addr}} Write {{data.reg_name}} {{data.value}}°C'
        }
    }

    def __init__(self):
        self._byte_pos: int = 0
        self._start_of_transaction = None
        self._start_of_frame = self._start_of_transaction
        self._end_of_frame = None
        self._read: bool = False
        self._for_us: bool = False
        self._reg_addr: int = 0
        self._reg_val_len: int = 2
        self._reg_val: int = 0

    def decode(self, frame: AnalyzerFrame):
        if 'error' in frame.data:
            return
        if frame.type == 'start':
            self._start_of_transaction = frame.start_time
            if self._byte_pos == 0:
                self._start_of_frame = frame.start_time
        elif frame.type == 'address':
            if frame.data['address'][0] & 0x78 == 0x48:
                self._i2c_addr = frame.data['address'][0]
                self._for_us = True
            else:
                self._for_us = False
                return
            self._read = frame.data['read']
        elif frame.type == 'data':
            if not self._for_us:
                return
            raw = frame.data['data'][0]
            if not self._read and self._byte_pos == 0:
                self._reg_addr = raw
                self._reg_val_len = 1 if self._reg_addr == 1 or self._reg_addr == 7 else 2 # only Configuration and ProductID has 1 byte value
            else:
                if self._byte_pos == 1:
                    if self._reg_val_len == 1:
                        self._reg_val = raw
                    else:
                        self._reg_val = raw << 8 # MSB first
                else:
                    self._reg_val += raw
            self._byte_pos += 1
        elif frame.type == 'stop':
            if not self._for_us:
                return
            if self._byte_pos == self._reg_val_len+1:
                analyzer_frame_type = "read_register" if self._read else "write_register"
                value_type = ""
                value = 0
                if self._reg_addr == 0 or self._reg_addr == 3 or self._reg_addr == 2:
                    value_type = "_temp"
                    value = float((self._reg_val & 0x7fff) >> 7) / 2
                    if self._reg_val & 0x8000 > 0:
                        value = -value
                analyzer_frame_type += value_type
                start_of_frame = self._start_of_frame
                # init vars
                self._byte_pos = 0
                self._start_of_frame = self._start_of_transaction
                return AnalyzerFrame(analyzer_frame_type, start_of_frame, frame.end_time, {
                    'i2c_addr': f"{self._i2c_addr}",
                    'reg_name': get_reg_name(self._reg_addr),
                    'value': f"{value:10.1f}" if value_type == "_temp" else f"0x{self._reg_val:X}"
                })
