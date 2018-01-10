#include <netinet/in.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <glib.h>
#include <NetworkManager.h>

int main(int argc, char** argv){
  struct hostent* host_info = gethostent();

  // 2 is AF_INET
  // 10 is AF_INET6
  for(int i = 0; i < 3; i++){
    printf("%d\n", host_info->h_addrtype);
    printf("%x\n", host_info->h_addr_list[i].sin_addr.s_addr);
  }
    
  return 0;
}
