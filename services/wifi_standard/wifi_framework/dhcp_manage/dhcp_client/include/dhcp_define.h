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
#ifndef OHOS_DHCP_DEFINE_H
#define OHOS_DHCP_DEFINE_H


#include <stdint.h>
#include <netinet/udp.h>
#include <netinet/ip.h>

#include "wifi_log.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NUMBER_ONE              1
#define NUMBER_TWO              2
#define NUMBER_THREE            3
#define NUMBER_FOUR             4
#define NUMBER_FIVE             5

#define T1                      0.5
#define T2                      0.875
#define TIME_INTERVAL_MAX       1
#define TIMEOUT_TIMES_MAX       6
#define TIMEOUT_WAIT_SEC        1
#define TIMEOUT_MORE_WAIT_SEC   60
#define ONE_HOURS_SEC           3600
#define LEASETIME_DEFAULT       1
#define SLEEP_TIME_200_MS       (200 * 1000)
#define SLEEP_TIME_500_MS       (500 * 1000)

#define MAC_ADDR_LEN            6
#define MAC_ADDR_CHAR_NUM       3
#define ETHERNET_TYPE           0x01
#define ETHERNET_LEN            6
#define VENDOR_MAX_LEN          64
#define MAGIC_COOKIE            0x63825363
#define BROADCAST_FLAG          0x8000
#define MAC_BCAST_ADDR          "\xff\xff\xff\xff\xff\xff"
#define SIGNED_INTEGER_MAX      0x7FFFFFFF
#define PID_MAX_LEN             16
#define DEFAULT_UMASK           027
#define DIR_MAX_LEN             256
#define INFNAME_SIZE            16    /* Length of interface name */

/* UDP port numbers for BOOTP */
#define BOOTP_SERVER            67
#define BOOTP_CLIENT            68

/* BOOTP message type */
#define BOOT_REQUEST            1
#define BOOT_REPLY              2

/* DHCP packet type */
#define DHCP_DISCOVER           1
#define DHCP_OFFER              2
#define DHCP_REQUEST            3
#define DHCP_DECLINE            4
#define DHCP_ACK                5
#define DHCP_NAK                6
#define DHCP_RELEASE            7
#define DHCP_INFORM             8
#define DHCP_FORCERENEW         9

/* dhcp state code */
enum EnumDhcpStateCode {
    DHCP_STATE_INIT = 0,
    DHCP_STATE_SELECTING,
    DHCP_STATE_REQUESTING,
    DHCP_STATE_BOUND,
    DHCP_STATE_RENEWING,
    DHCP_STATE_REBINDING,
    DHCP_STATE_RELEASED,
    DHCP_STATE_RENEWED,
};

/* dhcp return code */
enum EnumErrCode {
    /* success */
    DHCP_OPT_SUCCESS = 0,
    /* failed */
    DHCP_OPT_FAILED,
    /* null pointer */
    DHCP_OPT_NULL,
    /* timeout */
    DHCP_OPT_TIMEOUT,
    /* error */
    DHCP_OPT_ERROR,
    /* none */
    DHCP_OPT_NONE,
};

/* socket return code */
enum EnumSocketErrCode {
    /* success */
    SOCKET_OPT_SUCCESS = 0,
    /* failed */
    SOCKET_OPT_FAILED = -1,
    /* error */
    SOCKET_OPT_ERROR = -2
};

/* socket mode */
enum EnumSocketMode {
    SOCKET_MODE_INVALID        = 0,
    SOCKET_MODE_RAW            = 1,
    SOCKET_MODE_KERNEL         = 2
};

/* DHCP options */
enum EnumDhcpOption {
    DHO_PAD                    = 0,
    DHO_SUBNETMASK             = 1,
    DHO_ROUTER                 = 3,
    DHO_DNSSERVER              = 6,
    DHO_HOSTNAME               = 12,
    DHO_DNSDOMAIN              = 15,
    DHO_MTU                    = 26,
    DHO_BROADCAST              = 28,
    DHO_STATICROUTE            = 33,
    DHO_NISDOMAIN              = 40,
    DHO_NISSERVER              = 41,
    DHO_NTPSERVER              = 42,
    DHO_VENDOR                 = 43,
    DHO_IPADDRESS              = 50,
    DHO_LEASETIME              = 51,
    DHO_OPTSOVERLOADED         = 52,
    DHO_MESSAGETYPE            = 53,
    DHO_SERVERID               = 54,
    DHO_PARAMETERREQUESTLIST   = 55,
    DHO_MESSAGE                = 56,
    DHO_MAXMESSAGESIZE         = 57,
    DHO_RENEWALTIME            = 58,
    DHO_REBINDTIME             = 59,
    DHO_VENDORCLASSID          = 60,
    DHO_CLIENTID               = 61,
    DHO_USERCLASS              = 77,  /* RFC 3004 */
    DHO_RAPIDCOMMIT            = 80,  /* RFC 4039 */
    DHO_FQDN                   = 81,
    DHO_AUTHENTICATION         = 90,  /* RFC 3118 */
    DHO_AUTOCONFIGURE          = 116, /* RFC 2563 */
    DHO_DNSSEARCH              = 119, /* RFC 3397 */
    DHO_CSR                    = 121, /* RFC 3442 */
    DHO_VIVCO                  = 124, /* RFC 3925 */
    DHO_VIVSO                  = 125, /* RFC 3925 */
    DHO_FORCERENEW_NONCE       = 145, /* RFC 6704 */
    DHO_MUDURL                 = 161, /* draft-ietf-opsawg-mud */
    DHO_SIXRD                  = 212, /* RFC 5969 */
    DHO_MSCSR                  = 249, /* MS code for RFC 3442 */
    DHO_END                    = 255
};

enum DHCP_OPTION_DATA_TYPE {
    DHCP_OPTION_DATA_INVALID = 0,
    DHCP_OPTION_DATA_U8,
    DHCP_OPTION_DATA_U16,
    DHCP_OPTION_DATA_S16,
    DHCP_OPTION_DATA_U32,
    DHCP_OPTION_DATA_S32,
    DHCP_OPTION_DATA_IP,
    DHCP_OPTION_DATA_IP_PAIR,
    DHCP_OPTION_DATA_IP_LIST,
    DHCP_OPTION_DATA_IP_STRING
};

/* Sizes for DhcpPacket Fields */
#define	DHCP_CHADDR_MAX_BYTES       16
#define	DHCP_SNAME_MAX_BYTES        64
#define	DHCP_FILE_MAX_BYTES         128
#define DHCP_OPT_MAX_BYTES          308
#define DHCP_OPT_CODE_INDEX         0
#define DHCP_OPT_LEN_INDEX          1
#define DHCP_OPT_DATA_INDEX         2
#define DHCP_OPT_CODE_BYTES         1
#define DHCP_OPT_LEN_BYTES          1
#define DHCP_UINT8_BYTES            1
#define DHCP_UINT16_BYTES           2
#define DHCP_UINT32_BYTES           4
#define DHCP_UINT32_DOUBLE_BYTES    8
#define DHCP_UINT16_BITS            16
#define DHCP_REQ_CODE_NUM           10

#define OPTION_FIELD                0
#define FILE_FIELD                  1
#define SNAME_FIELD                 2

/* DhcpPacket Fields */
struct DhcpPacket {
    uint8_t op;         /* message type */
    uint8_t htype;      /* hardware address type */
    uint8_t hlen;       /* hardware address length */
    uint8_t hops;       /* should be zero in client message */
    uint32_t xid;       /* transaction id */
    uint16_t secs;      /* elapsed time in sec. from boot */
    uint16_t flags;     /* such as broadcast flag */
    uint32_t ciaddr;    /* (previously allocated) client IP */
    uint32_t yiaddr;    /* 'your' client IP address */
    uint32_t siaddr;    /* next server IP, should be zero in client's messages */
    uint32_t giaddr;    /* relay agent (gateway) IP, should be zero in client's messages */
    uint8_t chaddr[DHCP_CHADDR_MAX_BYTES];  /* client's hardware address */
    uint8_t sname[DHCP_SNAME_MAX_BYTES];    /* server host name */
    uint8_t file[DHCP_FILE_MAX_BYTES];      /* boot file name */
    int32_t cookie;                         /* magic cookie */
    uint8_t options[DHCP_OPT_MAX_BYTES];    /* dhcp options, Size: 312 - cookie */
};

struct UdpDhcpPacket {
    struct iphdr ip;
    struct udphdr udp;
    struct DhcpPacket data;
};

struct DhcpResult {
    char strYiaddr[INET_ADDRSTRLEN];        /* your (client) IP */
    char strOptServerId[INET_ADDRSTRLEN];   /* dhcp option DHO_SERVERID */
    char strOptSubnet[INET_ADDRSTRLEN];     /* dhcp option DHO_SUBNETMASK */
    char strOptDns1[INET_ADDRSTRLEN];       /* dhcp option DHO_DNSSERVER */
    char strOptDns2[INET_ADDRSTRLEN];       /* dhcp option DHO_DNSSERVER */
    char strOptRouter1[INET_ADDRSTRLEN];    /* dhcp option DHO_ROUTER */
    char strOptRouter2[INET_ADDRSTRLEN];    /* dhcp option DHO_ROUTER */
    char strOptVendor[DHCP_FILE_MAX_BYTES]; /* dhcp option DHO_VENDOR */
    uint32_t uOptLeasetime;                 /* dhcp option DHO_LEASETIME */
};

#ifdef __cplusplus
}
#endif
#endif
