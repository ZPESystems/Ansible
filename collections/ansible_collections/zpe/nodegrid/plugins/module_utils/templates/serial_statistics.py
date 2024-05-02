# TTP template
def get_template():
  template = '''
<group name="serial_connections">
  {{portnumber | exclude('-') | _start_ }}   {{device_name}}         {{speed}}  {{rx_bytes}}     {{tx_bytes}}      RTS DTR         {{cts_shift}}          {{dcd_shift}}          {{frame_error}}            {{overrun}}        {{parity_error}}             {{break}}      {{buffer_overrun}}
  {{portnumber | exclude('-') | _start_ }}   {{device_name}}         {{speed}}  {{rx_bytes}}     {{tx_bytes}}      RTS CTS DTR         {{cts_shift}}          {{dcd_shift}}          {{frame_error}}            {{overrun}}        {{parity_error}}             {{break}}      {{buffer_overrun}}
  {{portnumber | exclude('-') | _start_ }}   {{device_name}}         {{speed}}  {{rx_bytes}}     {{tx_bytes}}               {{cts_shift}}          {{dcd_shift}}          {{frame_error}}            {{overrun}}        {{parity_error}}             {{break}}      {{buffer_overrun}}
  {{portnumber | exclude('-') | _start_ }}   {{device_name}}         {{speed}}  {{rx_bytes}}     {{tx_bytes}}      RTS CTS DTR DSR CD         {{cts_shift}}          {{dcd_shift}}          {{frame_error}}            {{overrun}}        {{parity_error}}             {{break}}      {{buffer_overrun}}
  {{portnumber | exclude('-') | _start_ }}   {{device_name}}         {{speed}}  {{rx_bytes}}     {{tx_bytes}}      RTS DTR DSR CD         {{cts_shift}}          {{dcd_shift}}          {{frame_error}}            {{overrun}}        {{parity_error}}             {{break}}      {{buffer_overrun}}
</group>
'''
  return template