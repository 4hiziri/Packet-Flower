import gi
gi.require_version('NM', '1.0')
from gi.repository import NM
import dpkt

client = NM.Client.new(None)
dev = client.get_device_by_iface('enp4s0')
ipconfig = dev.get_ip4_config()
name_servers = ipconfig.get_nameservers()


