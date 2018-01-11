#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <NetworkManager.h>

const char* const * get_ip4_nameservers(char* interface);
const char* const * get_ip6_nameservers(char* interface);

int main(int argc, char** argv){
  if (argc != 2) {
    fprintf(stderr, "%s <interface>", argv[0]);
    exit(1);
  }

  char* interface = argv[1];
  
  const char* const* ip4_dns = get_ip4_nameservers(interface);
  const char* const* ip6_dns = get_ip6_nameservers(interface);

  if (ip4_dns) {
    for (int i = 0; ip4_dns[i]; i++)
      g_print("nameserver[%d]: %s\n", i, ip4_dns[i]);
  }

  if (ip6_dns) {
    for (int i = 0; ip6_dns[i]; i++)
      g_print("nameserver[%d]: %s\n", i, ip6_dns[i]);
  }

  return 0;
}

const char* const * get_ip4_nameservers(char *interface) {
  NMClient *client;
  NMDevice *device;
  NMIPConfig *ipconfig;
  const char* const* nameservers;

  client = nm_client_new(NULL, NULL);
  device = nm_client_get_device_by_iface(client, interface);  
  ipconfig = nm_device_get_ip4_config(device);
  nameservers = nm_ip_config_get_nameservers(ipconfig);

  return nameservers;
}

const char* const * get_ip6_nameservers(char *interface) {
  NMClient *client;
  NMDevice *device;
  NMIPConfig *ipconfig;
  const char* const* nameservers;

  client = nm_client_new(NULL, NULL);
  device = nm_client_get_device_by_iface(client, interface);
  ipconfig = nm_device_get_ip6_config(device);
  nameservers = nm_ip_config_get_nameservers(ipconfig);

  return nameservers;
}
