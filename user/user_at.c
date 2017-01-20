#include "ets_sys.h"
#include "osapi.h"
#include "at_custom.h"
#include "user_interface.h"

#include "user_webserver.h"

LOCAL char manufacturer[17], product[17], hwversion[9], fwversion[9];
LOCAL unsigned char estatus;

char *getmanufacturer(void)
{
	return manufacturer;
}
char *getproduct(void)
{
	return product;
}
char *gethwversion(void)
{
	return hwversion;
}
char *getfwversion(void)
{
	return fwversion;
}
int getstatus(void)
{
	return (int)estatus;
}

void ICACHE_FLASH_ATTR
at_setupCmdWebdev(uint8_t id, char *pPara)
{
int err = 1;
uint8 buffer1[17] = {0};
uint8 buffer2[17] = {0};

    pPara++;		// skip '='
    at_data_str_copy(buffer1, &pPara, 16);
    if (*pPara == ',') {
    	pPara++;	// skip ','
    	at_data_str_copy(buffer2, &pPara, 16);
	if (*pPara == '\r')
	    err = 0;
    }
    if(err == 0){
	    os_memcpy(manufacturer, buffer1, 17);
	    os_memcpy(product, buffer2, 17);
	    at_response_ok();
    } else {
        at_response_error();
    }
}

void ICACHE_FLASH_ATTR
at_setupCmdWebver(uint8_t id, char *pPara)
{
int err = 1;
uint8 buffer1[9] = {0};
uint8 buffer2[9] = {0};

    pPara++;		// skip '='
    at_data_str_copy(buffer1, &pPara, 8);
    if (*pPara == ',') {
    	pPara++;	// skip ','
    	at_data_str_copy(buffer2, &pPara, 8);
	if (*pPara == '\r')
	    err = 0;
    }
    if(err == 0){
	    os_memcpy(hwversion, buffer1, 9);
	    os_memcpy(fwversion, buffer2, 9);
	    at_response_ok();
    } else {
        at_response_error();
    }
}

void ICACHE_FLASH_ATTR
at_setupCmdWebsts(uint8_t id, char *pPara)
{
int result = 0, err = 0, flag = 0;

    pPara++;		// skip '='
    flag = at_get_next_int_dec(&pPara, &result, &err);

    if (flag || err || (result > 255) || (*pPara != '\r')) {
        at_response_error();
    } else {
	estatus = (unsigned char) result;
        at_response_ok();
    }
}

void ICACHE_FLASH_ATTR
at_testCmdWebdev(uint8_t id)
{
    at_port_print("+WEBDEV:\"Cika\",\"PDM\"\r\n");
    at_response_ok();
}

void ICACHE_FLASH_ATTR
at_testCmdWebver(uint8_t id)
{
    at_port_print("+WEBVER:\"hw.ver\",\"fw.ver\"\r\n");
    at_response_ok();
}

void ICACHE_FLASH_ATTR
at_testCmdWebsts(uint8_t id)
{
    at_port_print("+WEBSTS:(0-255)\r\n");
    at_response_ok();
}

void ICACHE_FLASH_ATTR
at_queryCmdWebdev(uint8_t id)
{
    uint8 buffer[48] = {0};	// 16 + 16 + local

    os_sprintf(buffer, "+WEBDEV:\"%s\",\"%s\"\r\n", manufacturer, product);
    at_port_print(buffer);
    at_response_ok();
}

void ICACHE_FLASH_ATTR
at_queryCmdWebver(uint8_t id)
{
    uint8 buffer[32] = {0};	// 8 + 8 + local

    os_sprintf(buffer, "+WEBVER:\"%s\",\"%s\"\r\n", hwversion, fwversion);
    at_port_print(buffer);
    at_response_ok();
}

void ICACHE_FLASH_ATTR
at_queryCmdWebsts(uint8_t id)
{
    uint8 buffer[32] = {0};

    os_sprintf(buffer, "+WEBSTS:%u\r\n", estatus);
    at_port_print(buffer);
    at_response_ok();
}

void ICACHE_FLASH_ATTR
at_exeCmdWebstart(uint8_t id)
{
int retval;

#ifdef SERVER_SSL_ENABLE
    retval = user_webserver_init(SERVER_SSL_PORT);
#else
    retval = user_webserver_init(SERVER_PORT);
#endif
    if(retval)
	at_response_error();
    else
	at_response_ok();
}

void ICACHE_FLASH_ATTR
at_exeCmdWebstop(uint8_t id)
{
    if(user_webserver_stop())
	at_response_error();
    else
	at_response_ok();
}


extern void at_exeCmdCiupdate(uint8_t id);
at_funcationType at_custom_cmd[] = {
    {"+WEBSTART", 9, NULL, NULL, NULL, at_exeCmdWebstart},
    {"+WEBSTOP", 8, NULL, NULL, NULL, at_exeCmdWebstop},
    {"+WEBDEV", 7, at_testCmdWebdev, at_queryCmdWebdev, at_setupCmdWebdev, NULL},
    {"+WEBVER", 7, at_testCmdWebver, at_queryCmdWebver, at_setupCmdWebver, NULL},
    {"+WEBSTS", 7, at_testCmdWebsts, at_queryCmdWebsts, at_setupCmdWebsts, NULL},
#ifdef AT_UPGRADE_SUPPORT
    {"+CIUPDATE", 9,       NULL,            NULL,            NULL, at_exeCmdCiupdate}
#endif
};

void ICACHE_FLASH_ATTR
user_at_init(void)
{
char buf[64] = {0};

    os_memcpy(manufacturer,"Cika",5);
    os_memcpy(product,"PDM",4);
    os_memcpy(hwversion,"w.z",4);
    os_memcpy(fwversion,"0.2",4);
    estatus = 0;
    at_customLinkMax = 5;
    at_init();
    os_sprintf(buf,"compile time:%s %s",__DATE__,__TIME__);
    at_set_custom_info(buf);
    at_cmd_array_regist(&at_custom_cmd[0], sizeof(at_custom_cmd)/sizeof(at_custom_cmd[0]));
}
