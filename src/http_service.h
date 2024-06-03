
#include <microhttpd.h>

struct MHD_Daemon *init_mhd(const char *interface, const int port,
                            const char *ssl_crt, const char *ssl_key);