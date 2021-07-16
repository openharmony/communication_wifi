/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef OHOS_DHCPC_H
#define OHOS_DHCPC_H

#include "dhcp_define.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WORKDIR                 "/data/dhcp/"
#define DHCPC_NAME              "dhcp_client_service"
#define DHCPC_CONF              "dhcp_client_service.conf"
#define DHCPC_PID               "dhcp_client_service.pid"
#define DHCPC_VERSION           "1.0"

enum DHCP_IP_TYPE {
    DHCP_IP_TYPE_NONE =  0,
    DHCP_IP_TYPE_ALL  =  1,
    DHCP_IP_TYPE_V4   =  2,
    DHCP_IP_TYPE_V6   =  3
};

struct DhcpClientCfg {
    char workdir[DIR_MAX_LEN];
    char confFile[DIR_MAX_LEN];
    char pidFile[DIR_MAX_LEN];
    char resultFile[DIR_MAX_LEN];
    char interface[INFNAME_SIZE];       /* The name of the interface to use */
    int  ifaceIndex;                    /* Index number of the interface to use */
    unsigned int ipaddr4;               /* ipv4 of the interface to use */
    unsigned int iptype;
    unsigned char hwaddr[MAC_ADDR_LEN]; /* HWaddr of the interface to use */

    unsigned char *clientid;            /* Optional client id to use */
    unsigned char *hostname;            /* Optional hostname to use */
    bool timeoutExit;                   /* Send packet timed out */
};

int StartProcess(void);
int StopProcess(const char *pidFile);
int GetProStatus(const char *pidFile);

struct DhcpClientCfg *GetDhcpClientCfg(void);

#ifdef __cplusplus
}
#endif
#endif
