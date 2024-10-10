def get_template():
  template = """
<group name="usb_devices">
  ========  ========  =========  =================  =============  ======================================================= {{ _start_ }}
  usb_port  usb_path  usb_id     detected_type      kernel_device  description  {{ _headers_ }}
</group>
"""
  return template