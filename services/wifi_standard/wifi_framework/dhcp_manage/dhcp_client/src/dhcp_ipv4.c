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
#include "dhcp_ipv4.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "securec.h"
#include "dhcp_client.h"
#include "dhcp_options.h"
#include "dhcp_socket.h"
#include "dhcp_function.h"

#undef LOG_TAG
#define LOG_TAG "WifiDhcpIpv4"

/* static defined */
static int g_dhcp4State = DHCP_STATE_INIT;
static int g_sockFd = -1;
static int g_sigSockFds[NUMBER_TWO];
static uint32_t g_sentPacketNum = 0;
static uint32_t g_timeoutTimestamp = 0;
static uint32_t g_renewalTimestamp = 0;
static uint32_t g_leaseTime = 0;
static uint32_t g_renewalSec = 0;
static uint32_t g_rebindSec = 0;
static uint32_t g_requestedIp4 = 0;
static uint32_t g_serverIp4 = 0;
static uint32_t g_socketMode = SOCKET_MODE_INVALID;
static uint32_t g_transID = 0;

static struct DhcpClientCfg *g_cltCnf;

/* Send signals. */
static void SignalHandler(int signum)
{
    switch (signum) {
        case SIGTERM:
            /* Send signal SIGTERM. */
        case SIGUSR1:
            /* Send signal SIGUSR1. */
        case SIGUSR2:
            /* Send signal SIGUSR2. */
            send(g_sigSockFds[1], &signum, sizeof(signum), MSG_DONTWAIT);
            break;
        default:
            break;
    }
}

/* Set the socket mode. */
static void SetSocketMode(uint32_t mode)
{
    close(g_sockFd);
    g_sockFd = -1;
    g_socketMode = mode;
    LOGI("SetSocketMode() the socket mode %{public}s.\n", (mode == SOCKET_MODE_RAW) ? "raw"
        : ((mode == SOCKET_MODE_KERNEL) ? "kernel" : "not valid"));
}

/* Execution dhcp release. */
static void ExecDhcpRelease(void)
{
    /* Ensure that we've received dhcp ack packet completely. */
    if ((g_dhcp4State == DHCP_STATE_BOUND) || (g_dhcp4State == DHCP_STATE_RENEWING) ||
        (g_dhcp4State == DHCP_STATE_REBINDING)) {
        /* Unicast dhcp release packet. */
        DhcpRelease(g_requestedIp4, g_serverIp4);
    }

    g_dhcp4State = DHCP_STATE_RELEASED;
    SetSocketMode(SOCKET_MODE_INVALID);

    /* Ensure that the function select() is always blocked and don't need to receive ip from dhcp server. */
    g_timeoutTimestamp = SIGNED_INTEGER_MAX;

    LOGI("ExecDhcpRelease() enter released state...\n");
}

/* Execution dhcp renew. */
static void ExecDhcpRenew(void)
{
    /* Set socket mode and dhcp ipv4 state, make sure dhcp packets can be sent normally. */
    switch (g_dhcp4State) {
        case DHCP_STATE_INIT:
        case DHCP_STATE_SELECTING:
            LOGI("ExecDhcpRenew() dhcp ipv4 old state:%{public}d, no need change state.\n", g_dhcp4State);
            break;
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RELEASED:
        case DHCP_STATE_RENEWED:
            LOGI("ExecDhcpRenew() dhcp ipv4 old state:%{public}d, init state:INIT.\n", g_dhcp4State);
            /* Init socket mode and dhcp ipv4 state. */
            g_dhcp4State = DHCP_STATE_INIT;
            SetSocketMode(SOCKET_MODE_RAW);
            break;
        case DHCP_STATE_BOUND:
            /* Set socket mode, send unicast packet. */
            SetSocketMode(SOCKET_MODE_KERNEL);
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:
            LOGI("ExecDhcpRenew() dhcp ipv4 old state:%{public}d, set state:RENEWED.\n", g_dhcp4State);
            /* Set dhcp ipv4 state, send request packet. */
            g_dhcp4State = DHCP_STATE_RENEWED;
            break;
        default:
            break;
    }

    /* Start record again, go back to init state. */
    g_sentPacketNum = 0;
    g_timeoutTimestamp = 0;

    LOGI("ExecDhcpRenew() a dhcp renew is executed...\n");
}

/* Add dhcp option paramater request list. */
static void AddParamaterRequestList(struct DhcpPacket *packet)
{
    int end = GetEndOptionIndex(packet->options);
    int i;
    int len = 0;
    uint8_t arrReqCode[DHCP_REQ_CODE_NUM] = {
        DHO_SUBNETMASK, DHO_ROUTER, DHO_DNSSERVER, DHO_HOSTNAME, DHO_DNSDOMAIN, DHO_BROADCAST};

    packet->options[end + DHCP_OPT_CODE_INDEX] = DHO_PARAMETERREQUESTLIST;
    for (i = 0; i < DHCP_REQ_CODE_NUM; i++) {
        if ((arrReqCode[i] > DHO_PAD) && (arrReqCode[i] < DHO_END)) {
            packet->options[end + DHCP_OPT_DATA_INDEX + len++] = arrReqCode[i];
        }
    }
    packet->options[end + DHCP_OPT_LEN_INDEX] = len;
    packet->options[end + DHCP_OPT_DATA_INDEX + len] = DHO_END;
}

/* Init the socket fd. */
static void InitSocketFd(void)
{
    if (g_sockFd < 0) {
        if (g_socketMode == SOCKET_MODE_INVALID) {
            return;
        }

        bool bInitSuccess = true;
        if (g_socketMode == SOCKET_MODE_RAW) {
            if ((CreateRawSocket(&g_sockFd) != SOCKET_OPT_SUCCESS) ||
                (BindRawSocket(g_sockFd, g_cltCnf->ifaceIndex, NULL) != SOCKET_OPT_SUCCESS)) {
                LOGE("InitSocketFd() fd:%{public}d,index:%{public}d failed!\n", g_sockFd, g_cltCnf->ifaceIndex);
                bInitSuccess = false;
            }
        } else {
            if ((CreateKernelSocket(&g_sockFd) != SOCKET_OPT_SUCCESS) ||
                (BindKernelSocket(g_sockFd, g_cltCnf->ifaceName, INADDR_ANY, BOOTP_CLIENT, true) !=
                    SOCKET_OPT_SUCCESS)) {
                LOGE("InitSocketFd() fd:%{public}d,ifname:%{public}s failed!\n", g_sockFd, g_cltCnf->ifaceName);
                bInitSuccess = false;
            }
        }
        if (!bInitSuccess || (g_sockFd < 0)) {
            LOGE("InitSocketFd() %{public}d err:%{public}s, couldn't listen on socket!\n", g_sockFd, strerror(errno));
            unlink(g_cltCnf->pidFile);
            unlink(g_cltCnf->resultFile);
            exit(EXIT_SUCCESS);
        }
    }
}

/* Obtains a random number as the trans id. */
static uint32_t GetTransId(void)
{
    static bool bSranded = false;
    if (!bSranded) {
        unsigned int uSeed = 0;
        int nFd = -1;
        if ((nFd = open("/dev/urandom", 0)) == -1) {
            LOGE("GetTransId() open /dev/urandom failed, error:%{public}s!\n", strerror(errno));
            uSeed = time(NULL);
        } else {
            if (read(nFd, &uSeed, sizeof(uSeed)) == -1) {
                LOGE("GetTransId() read /dev/urandom failed, error:%{public}s!\n", strerror(errno));
                uSeed = time(NULL);
            }
            LOGI("GetTransId() read /dev/urandom uSeed:%{public}u.\n", uSeed);
            close(nFd);
        }
        srandom(uSeed);
        bSranded = true;
    }
    return random();
}

static void InitSelecting(time_t timestamp)
{
    if (g_sentPacketNum > TIMEOUT_TIMES_MAX) {
        /* Send packet timed out, now exit process. */
        LOGW("InitSelecting() send packet timed out %{public}u times, now exit process!\n", g_sentPacketNum);
        g_timeoutTimestamp = timestamp + TIMEOUT_MORE_WAIT_SEC;
        g_sentPacketNum = 0;
        g_cltCnf->timeoutExit = true;
        return;
    }

    if (g_sentPacketNum == 0) {
        g_transID = GetTransId();
    }

    /* Broadcast dhcp discover packet. */
    DhcpDiscover(g_transID, g_requestedIp4);
    if (g_dhcp4State != DHCP_STATE_SELECTING) {
        g_dhcp4State = DHCP_STATE_SELECTING;
    }

    uint32_t uTimeoutSec = TIMEOUT_WAIT_SEC << g_sentPacketNum;
    g_timeoutTimestamp = timestamp + uTimeoutSec;
    LOGI("InitSelecting() DhcpDiscover g_sentPacketNum:%{public}u,timeoutSec:%{public}u,timestamp:%{public}u.\n",
        g_sentPacketNum,
        uTimeoutSec,
        g_timeoutTimestamp);

    g_sentPacketNum++;
}

static void Requesting(time_t timestamp)
{
    if (g_sentPacketNum > TIMEOUT_TIMES_MAX) {
        /* Send packet timed out, now enter init state. */
        g_dhcp4State = DHCP_STATE_INIT;
        SetSocketMode(SOCKET_MODE_RAW);
        g_sentPacketNum = 0;
        g_timeoutTimestamp = timestamp;
        return;
    }

    if (g_dhcp4State == DHCP_STATE_RENEWED) {
        /* Unicast dhcp request packet in the renew state. */
        DhcpRenew(g_transID, g_requestedIp4, g_serverIp4);
    } else {
        /* Broadcast dhcp request packet in the requesting state. */
        DhcpRequest(g_transID, g_requestedIp4, g_serverIp4);
    }

    uint32_t uTimeoutSec = TIMEOUT_WAIT_SEC << g_sentPacketNum;
    g_timeoutTimestamp = timestamp + uTimeoutSec;
    LOGI("Requesting() DhcpRequest g_sentPacketNum:%{public}u,timeoutSec:%{public}u,g_timeoutTimestamp:%{public}u.\n",
        g_sentPacketNum,
        uTimeoutSec,
        g_timeoutTimestamp);

    g_sentPacketNum++;
}

static void Renewing(time_t timestamp)
{
    if ((g_renewalSec + TIME_INTERVAL_MAX) < g_rebindSec) {
        /* Cur time is between renewal and rebind time, unicast dhcp request packet in the renew state. */
        DhcpRenew(g_transID, g_requestedIp4, g_serverIp4);

        /* Set a new renewal time. */
        g_renewalSec += (g_rebindSec - g_renewalSec) / NUMBER_TWO;
        g_timeoutTimestamp = g_renewalTimestamp + g_renewalSec;
        LOGI("Renewing() DhcpRenew unicast renewalTime:%{public}u,renewal:%{public}u,timeoutTime:%{public}u, "
                  "rebind:%{public}u.\n",
            g_renewalTimestamp,
            g_renewalSec,
            g_timeoutTimestamp,
            g_rebindSec);
    } else {
        /* Cur time reaches rebind time, now enter rebinding state. */
        g_dhcp4State = DHCP_STATE_REBINDING;
        LOGI("Renewing() cur time reaches rebind time, now enter rebinding state...\n");
        g_timeoutTimestamp = timestamp + (g_rebindSec - g_renewalSec);
        LOGI("Renewing() timestamp:%{public}d,rebind:%{public}u,renewal:%{public}u, timeoutTime:%{public}u.\n",
            (int)timestamp, g_rebindSec, g_renewalSec, g_timeoutTimestamp);
    }
}

static void Rebinding(time_t timestamp)
{
    if ((g_rebindSec + TIME_INTERVAL_MAX) < g_leaseTime) {
        /* Cur time is between rebind and lease time, broadcast dhcp request packet in the rebind state. */
        DhcpRenew(g_transID, g_requestedIp4, 0);

        /* Set a new rebind time. */
        g_rebindSec += (g_leaseTime - g_rebindSec) / NUMBER_TWO;
        g_timeoutTimestamp = g_renewalTimestamp + g_rebindSec;
        LOGI("Rebinding() DhcpRenew broadcast renewalTime:%{public}u,rebind:%{public}u,timeoutTime:%{public}u, "
                  "lease:%{public}u.\n",
            g_renewalTimestamp,
            g_rebindSec,
            g_timeoutTimestamp,
            g_leaseTime);
    } else {
        /* Cur time reaches lease time, send packet timed out, now enter init state. */
        LOGI("Rebinding() 555 cur time reaches lease time, now enter init state...\n");
        g_dhcp4State = DHCP_STATE_INIT;
        SetSocketMode(SOCKET_MODE_RAW);
        g_sentPacketNum = 0;
        g_timeoutTimestamp = timestamp;
        return;
    }
}

static void DhcpRequestHandle(time_t timestamp)
{
    switch (g_dhcp4State) {
        case DHCP_STATE_INIT:
        case DHCP_STATE_SELECTING:
            InitSelecting(timestamp);
            break;
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWED:
            Requesting(timestamp);
            break;
        case DHCP_STATE_BOUND:
            /* Now the renewal time run out, ready to enter renewing state. */
            LOGI("DhcpRequestHandle() 333 the renewal time run out, ready to enter renewing state...\n");
            g_dhcp4State = DHCP_STATE_RENEWING;
            SetSocketMode(SOCKET_MODE_KERNEL);
        case DHCP_STATE_RENEWING:
            Renewing(timestamp);
            break;
        case DHCP_STATE_REBINDING:
            Rebinding(timestamp);
            break;
        case DHCP_STATE_RELEASED:
            /* Ensure that the function select() is always blocked and don't need to receive ip from dhcp server. */
            g_timeoutTimestamp = SIGNED_INTEGER_MAX;
            break;
        default:
            break;
    }
}

static void DhcpOfferPacketHandle(uint8_t type, const struct DhcpPacket *packet, time_t timestamp)
{
    if (type != DHCP_OFFER) {
        LOGE("DhcpOfferPacketHandle() type:%{public}d error!\n", type);
        return;
    }

    if (packet == NULL) {
        LOGE("DhcpOfferPacketHandle() type:%{public}d error, packet == NULL!\n", type);
        return;
    }

    uint32_t u32Data = 0;
    if (!GetDhcpOptionUint32(packet, DHO_SERVERID, &u32Data)) {
        LOGE("DhcpOfferPacketHandle() type:%{public}d error, GetDhcpOptionUint32 DHO_SERVERID failed!\n", type);
        return;
    }

    g_transID = packet->xid;
    g_requestedIp4 = packet->yiaddr;
    g_serverIp4 = htonl(u32Data);

    char *pReqIp = Ip4IntConToStr(g_requestedIp4, false);
    if (pReqIp != NULL) {
        LOGI(
            "DhcpOfferPacketHandle() receive DHCP_OFFER, xid:%{public}u, requestIp: host %{private}u->%{private}s.\n",
            g_transID,
            ntohl(g_requestedIp4),
            pReqIp);
        free(pReqIp);
    }
    char *pSerIp = Ip4IntConToStr(g_serverIp4, false);
    if (pSerIp != NULL) {
        LOGI("DhcpOfferPacketHandle() receive DHCP_OFFER, serverIp: host %{private}u->%{private}s.\n",
            ntohl(g_serverIp4),
            pSerIp);
        free(pSerIp);
    }

    /* Receive dhcp offer packet finished, next send dhcp request packet. */
    g_dhcp4State = DHCP_STATE_REQUESTING;
    g_sentPacketNum = 0;
    g_timeoutTimestamp = timestamp;
}

static void ParseOtherNetworkInfo(const struct DhcpPacket *packet, struct DhcpResult *result)
{
    if ((packet == NULL) || (result == NULL)) {
        LOGE("ParseOtherNetworkInfo() error, packet == NULL or result == NULL!\n");
        return;
    }

    uint32_t u32Data = 0;
    uint32_t u32Data2 = 0;
    if (GetDhcpOptionUint32n(packet, DHO_DNSSERVER, &u32Data, &u32Data2)) {
        char *pDnsIp = Ip4IntConToStr(u32Data, true);
        if (pDnsIp != NULL) {
            LOGI("ParseOtherNetworkInfo() recv DHCP_ACK 6, dns1: %{private}u->%{private}s.\n", u32Data, pDnsIp);
            if (strncpy_s(result->strOptDns1, INET_ADDRSTRLEN, pDnsIp, INET_ADDRSTRLEN - 1) != EOK) {
                free(pDnsIp);
                return;
            }
            free(pDnsIp);
            pDnsIp = NULL;
        }
        if ((u32Data2 > 0) && ((pDnsIp = Ip4IntConToStr(u32Data2, true)) != NULL)) {
            LOGI("ParseOtherNetworkInfo() recv DHCP_ACK 6, dns2: %{private}u->%{private}s.\n", u32Data2, pDnsIp);
            if (strncpy_s(result->strOptDns2, INET_ADDRSTRLEN, pDnsIp, INET_ADDRSTRLEN - 1) != EOK) {
                free(pDnsIp);
                return;
            }
            free(pDnsIp);
        }
    }
}

static void ParseNetworkInfo(const struct DhcpPacket *packet, struct DhcpResult *result)
{
    if ((packet == NULL) || (result == NULL)) {
        LOGE("ParseNetworkInfo() error, packet == NULL or result == NULL!\n");
        return;
    }

    uint32_t u32Data = 0;
    if (GetDhcpOptionUint32(packet, DHO_SUBNETMASK, &u32Data)) {
        char *pSubIp = Ip4IntConToStr(u32Data, true);
        if (pSubIp != NULL) {
            LOGI("ParseNetworkInfo() recv DHCP_ACK 1, subnetmask: %{private}u->%{private}s.\n", u32Data, pSubIp);
            if (strncpy_s(result->strOptSubnet, INET_ADDRSTRLEN, pSubIp, INET_ADDRSTRLEN - 1) != EOK) {
                free(pSubIp);
                return;
            }
            free(pSubIp);
        }
    }

    u32Data = 0;
    uint32_t u32Data2 = 0;
    if (GetDhcpOptionUint32n(packet, DHO_ROUTER, &u32Data, &u32Data2)) {
        char *pRouterIp = Ip4IntConToStr(u32Data, true);
        if (pRouterIp != NULL) {
            LOGI("ParseNetworkInfo() recv DHCP_ACK 3, router1: %{private}u->%{private}s.\n", u32Data, pRouterIp);
            if (strncpy_s(result->strOptRouter1, INET_ADDRSTRLEN, pRouterIp, INET_ADDRSTRLEN - 1) != EOK) {
                free(pRouterIp);
                return;
            }
            free(pRouterIp);
            pRouterIp = NULL;
        }
        if ((u32Data2 > 0) && ((pRouterIp = Ip4IntConToStr(u32Data2, true)) != NULL)) {
            LOGI("ParseNetworkInfo() recv DHCP_ACK 3, router2: %{private}u->%{private}s.\n", u32Data2, pRouterIp);
            if (strncpy_s(result->strOptRouter2, INET_ADDRSTRLEN, pRouterIp, INET_ADDRSTRLEN - 1) != EOK) {
                free(pRouterIp);
                return;
            }
            free(pRouterIp);
        }
    }

    ParseOtherNetworkInfo(packet, result);
}

static void FormatString(struct DhcpResult *result)
{
    if (result == NULL) {
        LOGE("FormatString() error, result == NULL!\n");
        return;
    }

    if (strlen(result->strYiaddr) == 0) {
        if (strncpy_s(result->strYiaddr, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) != EOK) {
            return;
        }
    }
    if (strlen(result->strOptServerId) == 0) {
        if (strncpy_s(result->strOptServerId, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) != EOK) {
            return;
        }
    }
    if (strlen(result->strOptSubnet) == 0) {
        if (strncpy_s(result->strOptSubnet, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) != EOK) {
            return;
        }
    }
    if (strlen(result->strOptDns1) == 0) {
        if (strncpy_s(result->strOptDns1, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) != EOK) {
            return;
        }
    }
    if (strlen(result->strOptDns2) == 0) {
        if (strncpy_s(result->strOptDns2, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) != EOK) {
            return;
        }
    }
    if (strlen(result->strOptRouter1) == 0) {
        if (strncpy_s(result->strOptRouter1, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) != EOK) {
            return;
        }
    }
    if (strlen(result->strOptRouter2) == 0) {
        if (strncpy_s(result->strOptRouter2, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) != EOK) {
            return;
        }
    }
    if (strlen(result->strOptVendor) == 0) {
        if (strncpy_s(result->strOptVendor, DHCP_FILE_MAX_BYTES, "*", DHCP_FILE_MAX_BYTES - 1) != EOK) {
            return;
        }
    }
}

static void WriteDhcpResult(struct DhcpResult *result)
{
    if (result == NULL) {
        LOGE("WriteDhcpResult() error, result == NULL!\n");
        return;
    }

    /* Format dhcp result. */
    FormatString(result);

    uint32_t curTime = (uint32_t)time(NULL);
    LOGI("WriteDhcpResult() "
         "result->strYiaddr:%{private}s,strOptServerId:%{private}s,strOptSubnet:%{private}s,uOptLeasetime:%{public}u,"
         " curTime:%{public}u.\n",
        result->strYiaddr, result->strOptServerId, result->strOptSubnet, result->uOptLeasetime, curTime);
    FILE *pFile = fopen(g_cltCnf->resultFile, "w+");
    if (pFile == NULL) {
        LOGE("WriteDhcpResult fopen %{public}s err:%{public}s!\n", g_cltCnf->resultFile, strerror(errno));
        return;
    }

    /* Lock the writing file. */
    if (flock(fileno(pFile), LOCK_EX) != 0) {
        LOGE("WriteDhcpResult() flock file:%{public}s LOCK_EX failed, error:%{public}s!\n",
            g_cltCnf->resultFile,
            strerror(errno));
        fclose(pFile);
        return;
    }

    /* Format: IP4 timestamp cliIp servIp subnet dns1 dns2 router1 router2 vendor lease. */
    int nBytes = fprintf(pFile,
        "IP4 %u %s %s %s %s %s %s %s %s %u\n",
        curTime, result->strYiaddr, result->strOptServerId, result->strOptSubnet, result->strOptDns1,
        result->strOptDns2, result->strOptRouter1, result->strOptRouter2, result->strOptVendor, result->uOptLeasetime);
    if (nBytes <= 0) {
        LOGE("WriteDhcpResult() fprintf %{public}s error:%{public}s!\n", g_cltCnf->resultFile, strerror(errno));
        fclose(pFile);
        return;
    }
    LOGI("WriteDhcpResult() fprintf %{public}s success, nBytes:%{public}d.\n", g_cltCnf->resultFile, nBytes);

    /* Unlock the writing file. */
    if (flock(fileno(pFile), LOCK_UN) != 0) {
        LOGE("WriteDhcpResult() flock file:%{public}s LOCK_UN failed, error:%{public}s!\n",
            g_cltCnf->resultFile, strerror(errno));
        fclose(pFile);
        return;
    }

    if (fclose(pFile) != 0) {
        LOGE("WriteDhcpResult() fclose %{public}s error:%{public}s!\n", g_cltCnf->resultFile, strerror(errno));
        return;
    }
}

static void SyncDhcpResult(const struct DhcpPacket *packet, struct DhcpResult *result)
{
    if ((packet == NULL) || (result == NULL)) {
        LOGE("SyncDhcpResult() error, packet == NULL or result == NULL!\n");
        return;
    }

    char *pVendor = GetDhcpOptionString(packet, DHO_VENDOR);
    if (pVendor == NULL) {
        LOGW("SyncDhcpResult() recv DHCP_ACK 43, pVendor is NULL!\n");
    } else {
        LOGI("SyncDhcpResult() recv DHCP_ACK 43, pVendor is %{public}s.\n", pVendor);
        if (strncpy_s(result->strOptVendor, DHCP_FILE_MAX_BYTES, pVendor, DHCP_FILE_MAX_BYTES - 1) != EOK) {
            free(pVendor);
            return;
        }
        free(pVendor);
    }

    /* Set the specified client process interface network info. */
    if (SetLocalInterface(g_cltCnf->ifaceName, ntohl(g_requestedIp4)) != DHCP_OPT_SUCCESS) {
        LOGE("SyncDhcpResult() error, SetLocalInterface yiaddr:%{private}s failed!\n", result->strYiaddr);
        return;
    }

    /* Wirte to the file. */
    WriteDhcpResult(result);
}

static void ParseDhcpAckPacket(const struct DhcpPacket *packet, time_t timestamp)
{
    if (packet == NULL) {
        return;
    }

    struct DhcpResult dhcpResult;
    if (memset_s(&dhcpResult, sizeof(struct DhcpResult), 0, sizeof(struct DhcpResult)) != EOK) {
        return;
    }

    /* Set default leasetime. */
    g_leaseTime = LEASETIME_DEFAULT * ONE_HOURS_SEC;
    g_requestedIp4 = packet->yiaddr;
    uint32_t u32Data = 0;
    if (GetDhcpOptionUint32(packet, DHO_LEASETIME, &u32Data)) {
        g_leaseTime = u32Data;
        LOGI("ParseDhcpAckPacket() recv DHCP_ACK 51, lease:%{public}u.\n", g_leaseTime);
    }
    g_renewalSec = g_leaseTime * T1;    /* First renewal seconds. */
    g_rebindSec  = g_leaseTime * T2;    /* Second rebind seconds. */
    g_renewalTimestamp = timestamp;   /* Record begin renewing or rebinding timestamp. */
    dhcpResult.uOptLeasetime = g_leaseTime;

    u32Data = 0;
    if (!GetDhcpOptionUint32(packet, DHO_SERVERID, &u32Data)) {
        LOGW("ParseDhcpAckPacket() GetDhcpOptionUint32 DHO_SERVERID failed!\n");
    } else {
        g_serverIp4 = htonl(u32Data);
    }

    LOGI("recv ACK 51 lease:%{public}u,new:%{public}u,bind:%{public}u.\n", g_leaseTime, g_renewalSec, g_rebindSec);
    char *pReqIp = Ip4IntConToStr(g_requestedIp4, false);
    if (pReqIp != NULL) {
        LOGI("ParseDhcpAckPacket() recv DHCP_ACK yiaddr: %{private}u->%{private}s.\n", ntohl(g_requestedIp4), pReqIp);
        if (strncpy_s(dhcpResult.strYiaddr, INET_ADDRSTRLEN, pReqIp, INET_ADDRSTRLEN - 1) != EOK) {
            free(pReqIp);
            return;
        }
        free(pReqIp);
    }
    char *pSerIp = Ip4IntConToStr(g_serverIp4, false);
    if (pSerIp != NULL) {
        LOGI("ParseDhcpAckPacket() recv DHCP_ACK 54, serid: %{private}u->%{private}s.\n", ntohl(g_serverIp4), pSerIp);
        if (strncpy_s(dhcpResult.strOptServerId, INET_ADDRSTRLEN, pSerIp, INET_ADDRSTRLEN - 1) != EOK) {
            free(pSerIp);
            return;
        }
        free(pSerIp);
    }

    /* Parse the specified client process interface network info. */
    ParseNetworkInfo(packet, &dhcpResult);

    /* Sync the specified client process interface network info to the file. */
    SyncDhcpResult(packet, &dhcpResult);

    /* Receive dhcp ack packet finished, g_leaseTime * T1 later enter renewing state. */
    g_dhcp4State = DHCP_STATE_BOUND;
    SetSocketMode(SOCKET_MODE_INVALID);
    g_timeoutTimestamp = timestamp + g_renewalSec;
}

static void DhcpAckOrNakPacketHandle(uint8_t type, struct DhcpPacket *packet, time_t timestamp)
{
    if ((type != DHCP_ACK) && (type != DHCP_NAK)) {
        LOGE("DhcpAckOrNakPacketHandle() type:%{public}d error!\n", type);
        return;
    }

    if (packet == NULL) {
        LOGE("DhcpAckOrNakPacketHandle() type:%{public}d error, packet == NULL!\n", type);
        return;
    }

    if (type == DHCP_NAK) {
        /* If receive dhcp nak packet, init g_dhcp4State, resend dhcp discover packet. */
        LOGI("DhcpAckOrNakPacketHandle() receive DHCP_NAK 53, init g_dhcp4State, resend dhcp discover packet!\n");
        g_dhcp4State = DHCP_STATE_INIT;
        SetSocketMode(SOCKET_MODE_RAW);
        g_requestedIp4 = 0;
        g_sentPacketNum = 0;
        g_timeoutTimestamp = timestamp;

        /* Avoid excessive network traffic. */
        LOGI("DhcpAckOrNakPacketHandle() receive DHCP_NAK 53, avoid excessive network traffic, need sleep!\n");
        sleep(NUMBER_THREE);
        return;
    }

    LOGI("DhcpAckOrNakPacketHandle() recv DHCP_ACK 53.\n");

    /* Parse received dhcp ack packet. */
    ParseDhcpAckPacket(packet, timestamp);
}

static void DhcpResponseHandle(time_t timestamp)
{
    struct DhcpPacket packet;
    int getLen;
    uint8_t u8Message = 0;

    if (memset_s(&packet, sizeof(packet), 0, sizeof(packet)) != EOK) {
        LOGE("DhcpResponseHandle() memset_s packet failed!\n");
        return;
    }
    getLen = (g_socketMode == SOCKET_MODE_RAW) ? GetDhcpRawPacket(&packet, g_sockFd)
                                               : GetDhcpKernelPacket(&packet, g_sockFd);
    if (getLen < 0) {
        if ((getLen == SOCKET_OPT_ERROR) && (errno != EINTR)) {
            LOGE("DhcpResponseHandle() get packet read error, reopening socket!\n");
            /* Reopen g_sockFd. */
            SetSocketMode(g_socketMode);
        }
        LOGE("DhcpResponseHandle() get packet failed, error:%{public}s!\n", strerror(errno));
        return;
    }
    LOGI("DhcpResponseHandle() get packet success, getLen:%{public}d.\n", getLen);

    /* Check packet data. */
    if (packet.xid != g_transID) {
        LOGW("DhcpResponseHandle() get xid:%{public}u and g_transID:%{public}u not same!\n", packet.xid, g_transID);
        return;
    }
    if (!GetDhcpOptionUint8(&packet, DHO_MESSAGETYPE, &u8Message)) {
        LOGE("DhcpResponseHandle() GetDhcpOptionUint8 DHO_MESSAGETYPE failed!\n");
        return;
    }

    switch (g_dhcp4State) {
        case DHCP_STATE_SELECTING:
            DhcpOfferPacketHandle(u8Message, &packet, timestamp);
            break;
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:
        case DHCP_STATE_RENEWED:
            DhcpAckOrNakPacketHandle(u8Message, &packet, timestamp);
            break;
        case DHCP_STATE_BOUND:
        case DHCP_STATE_RELEASED:
            LOGW("DhcpResponseHandle() g_dhcp4State is BOUND or RELEASED, ignore all packets!\n");
            break;
        default:
            break;
    }
}

/* Receive signals. */
static void SignalReceiver(void)
{
    int signum;
    if (read(g_sigSockFds[0], &signum, sizeof(signum)) < 0) {
        LOGE("SignalReceiver() failed, g_sigSockFds[0]:%{public}d read error:%{public}s!\n",
            g_sigSockFds[0], strerror(errno));
        return;
    }

    switch (signum) {
        case SIGTERM:
            LOGW("SignalReceiver() SIGTERM!\n");
            SetSocketMode(SOCKET_MODE_INVALID);
            unlink(g_cltCnf->pidFile);
            unlink(g_cltCnf->resultFile);
            exit(EXIT_SUCCESS);
            break;
        case SIGUSR1:
            LOGW("SignalReceiver() SIGUSR1!\n");
            ExecDhcpRelease();
            break;
        case SIGUSR2:
            LOGW("SignalReceiver() SIGUSR2!\n");
            ExecDhcpRenew();
            break;
        default:
            break;
    }
}


/* Set dhcp ipv4 state. */
int SetIpv4State(int state)
{
    if (state < 0) {
        LOGE("SetIpv4State() failed, state:%{public}d!\n", state);
        return DHCP_OPT_FAILED;
    }

    g_dhcp4State = state;
    return DHCP_OPT_SUCCESS;
}

/* Init signal handle function. */
int InitSignalHandle(void)
{
    /* Create signal socket fd. */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_sigSockFds) != 0) {
        LOGE("InitSignalHandle() failed, socketpair error str:%{public}s!\n", strerror(errno));
        return DHCP_OPT_FAILED;
    }

    /* Register signal handlers. */
    if (signal(SIGTERM, SignalHandler) == SIG_ERR) {
        LOGE("InitSignalHandle() failed, signal SIGTERM error str:%{public}s!\n", strerror(errno));
        return DHCP_OPT_FAILED;
    }

    if (signal(SIGUSR1, SignalHandler) == SIG_ERR) {
        LOGE("InitSignalHandle() failed, signal SIGUSR1 error str:%{public}s!\n", strerror(errno));
        return DHCP_OPT_FAILED;
    }

    if (signal(SIGUSR2, SignalHandler) == SIG_ERR) {
        LOGE("InitSignalHandle() failed, signal SIGUSR2 error str:%{public}s!\n", strerror(errno));
        return DHCP_OPT_FAILED;
    }

    return DHCP_OPT_SUCCESS;
}

int GetPacketHeaderInfo(struct DhcpPacket *packet, uint8_t type)
{
    if (packet == NULL) {
        LOGE("GetPacketHeaderInfo() failed, packet == NULL!\n");
        return DHCP_OPT_FAILED;
    }

    switch (type) {
        case DHCP_DISCOVER:
        case DHCP_REQUEST:
        case DHCP_RELEASE:
        case DHCP_INFORM:
            packet->op = BOOT_REQUEST;
            break;
        case DHCP_OFFER:
        case DHCP_ACK:
        case DHCP_NAK:
            packet->op = BOOT_REPLY;
            break;
        default:
            break;
    }
    packet->htype = ETHERNET_TYPE;
    packet->hlen = ETHERNET_LEN;
    packet->cookie = htonl(MAGIC_COOKIE);
    packet->options[0] = DHO_END;
    AddOptValueToOpts(packet->options, DHO_MESSAGETYPE, type);

    return DHCP_OPT_SUCCESS;
}

int GetPacketCommonInfo(struct DhcpPacket *packet)
{
    if (packet == NULL) {
        LOGE("GetPacketCommonInfo() failed, packet == NULL!\n");
        return DHCP_OPT_FAILED;
    }

    /* Add packet client_cfg info. */
    if (memcpy_s(packet->chaddr, sizeof(packet->chaddr), g_cltCnf->ifaceMac, MAC_ADDR_LEN) != EOK) {
        LOGE("GetPacketCommonInfo() failed, memcpy_s error!\n");
        return DHCP_OPT_FAILED;
    }
    int nClientIdLen = DHCP_OPT_CODE_BYTES + DHCP_OPT_LEN_BYTES + g_cltCnf->pOptClientId[DHCP_OPT_LEN_INDEX];
    AddOptStrToOpts(packet->options, g_cltCnf->pOptClientId, nClientIdLen);

    /* Add packet vendor info, vendor format: pro-version. */
    char buf[VENDOR_MAX_LEN - DHCP_OPT_CODE_BYTES - DHCP_OPT_LEN_BYTES] = {0};
    unsigned char vendorId[VENDOR_MAX_LEN] = {0};
    unsigned char *pVendorId = vendorId;
    int nRes = snprintf_s(buf,
        VENDOR_MAX_LEN - DHCP_OPT_DATA_INDEX,
        VENDOR_MAX_LEN - DHCP_OPT_DATA_INDEX - 1,
        "%s-%s",
        DHCPC_NAME,
        DHCPC_VERSION);
    if (nRes < 0) {
        LOGE("GetPacketCommonInfo() failed, snprintf_s res:%{public}d error!\n", nRes);
        return DHCP_OPT_FAILED;
    }
    pVendorId[DHCP_OPT_CODE_INDEX] = DHO_VENDOR;
    pVendorId[DHCP_OPT_LEN_INDEX] = strlen(buf);
    if (strncpy_s((char *)pVendorId + DHCP_OPT_DATA_INDEX, VENDOR_MAX_LEN - DHCP_OPT_DATA_INDEX, buf, strlen(buf)) !=
        EOK) {
        LOGE("GetPacketCommonInfo() failed, strncpy_s error!\n");
        return DHCP_OPT_FAILED;
    }
    if (strlen((char *)vendorId) > 0) {
        int nVendorIdLen = DHCP_OPT_CODE_BYTES + DHCP_OPT_LEN_BYTES + pVendorId[DHCP_OPT_LEN_INDEX];
        AddOptStrToOpts(packet->options, vendorId, nVendorIdLen);
    }

    return DHCP_OPT_SUCCESS;
}

/* Broadcast dhcp discover packet, discover dhcp servers that can provide ip address. */
int DhcpDiscover(uint32_t transid, uint32_t requestip)
{
    LOGI("DhcpDiscover() enter, transid:%{public}u,requestip:%{private}u.\n", transid, requestip);

    struct DhcpPacket packet;
    if (memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket)) != EOK) {
        return -1;
    }

    /* Get packet header and common info. */
    if ((GetPacketHeaderInfo(&packet, DHCP_DISCOVER) != DHCP_OPT_SUCCESS) ||
        (GetPacketCommonInfo(&packet) != DHCP_OPT_SUCCESS)) {
        return -1;
    }

    /* Get packet not common info. */
    packet.xid = transid;
    if (requestip > 0) {
        AddOptValueToOpts(packet.options, DHO_IPADDRESS, requestip);
    }
    AddParamaterRequestList(&packet);

    /* Begin broadcast dhcp discover packet. */
    LOGI("DhcpDiscover() discover, begin broadcast discover packet...\n");
    return SendToDhcpPacket(&packet, INADDR_ANY, INADDR_BROADCAST, g_cltCnf->ifaceIndex, (uint8_t *)MAC_BCAST_ADDR);
}

/* Broadcast dhcp request packet, tell dhcp servers that which ip address to choose. */
int DhcpRequest(uint32_t transid, uint32_t reqip, uint32_t servip)
{
    LOGI("DhcpRequest() enter, transid:%{public}u,reqip:%{private}u.\n", transid, reqip);

    struct DhcpPacket packet;
    if (memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket)) != EOK) {
        return -1;
    }

    /* Get packet header and common info. */
    if ((GetPacketHeaderInfo(&packet, DHCP_REQUEST) != DHCP_OPT_SUCCESS) ||
        (GetPacketCommonInfo(&packet) != DHCP_OPT_SUCCESS)) {
        return -1;
    }

    /* Get packet not common info. */
    packet.xid = transid;
    AddOptValueToOpts(packet.options, DHO_IPADDRESS, reqip);
    AddOptValueToOpts(packet.options, DHO_SERVERID, servip);
    AddParamaterRequestList(&packet);

    /* Begin broadcast dhcp request packet. */
    char *pReqIp = Ip4IntConToStr(reqip, false);
    if (pReqIp != NULL) {
        LOGI("DhcpRequest() broadcast req packet, reqip: host %{private}u->%{private}s.\n", ntohl(reqip), pReqIp);
        free(pReqIp);
    }
    char *pSerIp = Ip4IntConToStr(servip, false);
    if (pSerIp != NULL) {
        LOGI("DhcpRequest() broadcast req packet, servIp: host %{private}u->%{private}s.\n", ntohl(servip), pSerIp);
        free(pSerIp);
    }
    return SendToDhcpPacket(&packet, INADDR_ANY, INADDR_BROADCAST, g_cltCnf->ifaceIndex, (uint8_t *)MAC_BCAST_ADDR);
}

/* Unicast or broadcast dhcp request packet, request to extend the lease from the dhcp server. */
int DhcpRenew(uint32_t transid, uint32_t clientip, uint32_t serverip)
{
    LOGI("DhcpRenew() enter, transid:%{public}u,clientip:%{private}u.\n", transid, clientip);

    struct DhcpPacket packet;
    if (memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket)) != EOK) {
        return -1;
    }

    /* Get packet header and common info. */
    if ((GetPacketHeaderInfo(&packet, DHCP_REQUEST) != DHCP_OPT_SUCCESS) ||
        (GetPacketCommonInfo(&packet) != DHCP_OPT_SUCCESS)) {
        return -1;
    }

    /* Get packet not common info. */
    packet.xid = transid;
    packet.ciaddr = clientip;
    AddParamaterRequestList(&packet);

    /* Begin broadcast or unicast dhcp request packet. */
    struct in_addr serverAddr;
    serverAddr.s_addr = serverip;
    if (serverip == 0) {
        LOGI("DhcpRenew() rebind, begin broadcast req packet, serverip:%{private}s...\n", inet_ntoa(serverAddr));
        return SendToDhcpPacket(&packet, INADDR_ANY, INADDR_BROADCAST, g_cltCnf->ifaceIndex, (uint8_t *)MAC_BCAST_ADDR);
    }
    LOGI("DhcpRenew() renew, begin unicast request packet, serverip:%{private}s...\n", inet_ntoa(serverAddr));
    return SendDhcpPacket(&packet, clientip, serverip);
}

/* Unicast dhcp release packet, releasing an ip address in Use from the dhcp server. */
int DhcpRelease(uint32_t clientip, uint32_t serverip)
{
    LOGI("DhcpRelease() enter, clientip:%{private}u.\n", clientip);

    struct DhcpPacket packet;
    if (memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket)) != EOK) {
        return -1;
    }

    /* Get packet header and common info. */
    if ((GetPacketHeaderInfo(&packet, DHCP_RELEASE) != DHCP_OPT_SUCCESS) ||
        (GetPacketCommonInfo(&packet) != DHCP_OPT_SUCCESS)) {
        return -1;
    }

    /* Get packet not common info. */
    packet.xid = GetTransId();
    AddOptValueToOpts(packet.options, DHO_IPADDRESS, clientip);
    AddOptValueToOpts(packet.options, DHO_SERVERID, serverip);

    /* Begin unicast dhcp release packet. */
    struct in_addr requestAddr, serverAddr;
    requestAddr.s_addr = clientip;
    serverAddr.s_addr = serverip;
    LOGI("DhcpRelease() release, begin unicast release packet, clientip:%{private}s,", inet_ntoa(requestAddr));
    LOGI("serverip:%{private}s...\n", inet_ntoa(serverAddr));
    return SendDhcpPacket(&packet, clientip, serverip);
}

int StartIpv4(void)
{
    int nRet, nMaxFds;
    fd_set exceptfds;
    struct timeval timeout;
    time_t curTimestamp;

    g_cltCnf = GetDhcpClientCfg();

    /* Init dhcp ipv4 state. */
    g_dhcp4State = DHCP_STATE_INIT;
    SetSocketMode(SOCKET_MODE_RAW);

    for (; ;) {
        if (g_cltCnf->timeoutExit) {
            LOGW("StartIpv4() send packet timed out, now break!\n");
            break;
        }

        FD_ZERO(&exceptfds);
        timeout.tv_sec = g_timeoutTimestamp - time(NULL);
        timeout.tv_usec = 0;

        InitSocketFd();

        if (g_sockFd >= 0) {
            FD_SET(g_sockFd, &exceptfds);
        }
        FD_SET(g_sigSockFds[0], &exceptfds);

        if (timeout.tv_sec <= 0) {
            LOGI("StartIpv4() already timed out, need send or resend packet...\n");
            nRet = 0;
        } else {
            LOGI("StartIpv4() waiting on select...\n");
            nMaxFds = (g_sigSockFds[0] > g_sockFd) ? g_sigSockFds[0] : g_sockFd;
            nRet = select(nMaxFds + 1, &exceptfds, NULL, NULL, &timeout);
        }
        if (nRet < 0) {
            if ((nRet == -1) && (errno == EINTR)) {
                LOGW("StartIpv4() select err:%{public}s, a signal was caught!\n", strerror(errno));
            } else {
                LOGE("StartIpv4() failed, select maxFds:%{public}d error:%{public}s!\n", nMaxFds, strerror(errno));
            }
            continue;
        }

        curTimestamp = time(NULL);
        if (nRet == 0) {
            DhcpRequestHandle(curTimestamp);
        } else if ((g_socketMode != SOCKET_MODE_INVALID) && FD_ISSET(g_sockFd, &exceptfds)) {
            DhcpResponseHandle(curTimestamp);
        } else if (FD_ISSET(g_sigSockFds[0], &exceptfds)) {
            SignalReceiver();
        } else {
            LOGW("StartIpv4() nRet:%{public}d, g_socketMode:%{public}d, continue select...\n", nRet, g_socketMode);
        }
    }
    return g_cltCnf->timeoutExit ? StopProcess(g_cltCnf->pidFile) : DHCP_OPT_SUCCESS;
}