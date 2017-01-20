#ifndef __USER_CONFIG_H__
#define __USER_CONFIG_H__

#define AT_CUSTOM_UPGRADE

#define USE_OPTIMIZE_PRINTF


//#define SERVER_SSL_ENABLE
//#define CLIENT_SSL_ENABLE
//#define UPGRADE_SSL_ENABLE

//#define SOFTAP_ENCRYPT

#ifdef SOFTAP_ENCRYPT
#define PASSWORD	"v*%W>L<@i&Nxe!"
#endif



#ifdef AT_CUSTOM_UPGRADE
    #ifndef AT_UPGRADE_SUPPORT
    #error "upgrade is not supported when eagle.flash.bin+eagle.irom0text.bin!!!"
    #endif
#endif

#endif
