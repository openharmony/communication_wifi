/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "wifi_wpa_hal.h"
#include <poll.h>
#include <unistd.h>
#include "securec.h"
#include "wifi_common_def.h"
#include "wifi_hal_callback.h"
#include "wifi_hal_common_func.h"
#include "wifi_hal_p2p_struct.h"
#include "wifi_hal_struct.h"
#include "wifi_p2p_hal.h"
#include "wifi_wpa_common.h"
#include "wifi_hal_sta_interface.h"
#include "wifi_hal_ap_interface.h"
#include "wifi_hal_p2p_interface.h"
#include "wifi_hal_module_manage.h"
#include "wifi_common_hal.h"

#ifndef __UT__
#include "wifi_log.h"
#endif

#ifdef __UT__
#define static
#define LOGI(...) ;
#define LOGD(...) ;
#define LOGE(...) ;
#endif

#undef LOG_TAG
#define LOG_TAG "WifiWpaHal"

#define WPA_TRY_CONNECT_TIMES 20
#define WPA_TRY_CONNECT_SLEEP_TIME (100 * 1000) /* 100ms */
#define WPA_CMD_BUF_LEN 256
#define WPA_CMD_REPLY_BUF_SMALL_LEN 64
#define P2P_SERVICE_INFO_FIRST_SECTION 1
#define P2P_SERVICE_INFO_SECOND_SECTION 2
#define P2P_SERVICE_INFO_THIRD_SECTION 3
#define P2P_SERVICE_DISC_REQ_ONE 1
#define P2P_SERVICE_DISC_REQ_TWO 2
#define P2P_SERVICE_DISC_REQ_THREE 3
#define P2P_SERVICE_DISC_REQ_FOUR 4
#define P2P_SERVICE_DISC_REQ_FIVE 5
#define WPA_CB_CONNECTED 1
#define WPA_CB_DISCONNECTED 2
#define WPA_CB_ASSOCIATING 3
#define WPA_CB_ASSOCIATED 4
#define WPS_EVENT_PBC_OVERLAP "WPS-OVERLAP-DETECTED PBC session overlap"
#define WPA_EVENT_BSSID_CHANGED "WPA-EVENT-BSSID-CHANGED "
#define WPA_EVENT_ASSOCIATING "Request association with "
#define WPA_EVENT_ASSOCIATED "Associated with "
#define REPLY_BUF_LENGTH 4096
#define CONNECTION_PWD_WRONG_STATUS 1
#define CONNECTION_FULL_STATUS 17
#define CONNECTION_REJECT_STATUS 37
#define WLAN_STATUS_AUTH_TIMEOUT 16
#define MAC_AUTH_RSP2_TIMEOUT 5201
#define MAC_AUTH_RSP4_TIMEOUT 5202
#define MAC_ASSOC_RSP_TIMEOUT 5203
#define SSID_EMPTY_LENGTH 1

#ifdef WPA_CTRL_IFACE_UNIX
#define WPA_CTRL_OPEN_IFNAME "@abstract:"CONFIG_ROOR_DIR"/sockets/wpa/wlan0"
#else
#define WPA_CTRL_OPEN_IFNAME ""CONFIG_ROOR_DIR"/sockets/wpa"
#endif // WPA_CTRL_IFACE_UNIX

static WifiWpaInterface *g_wpaInterface = NULL;

/* Detailed device string pattern from wpa_supplicant with WFD info
 * Example: P2P-DEVICE-FOUND 00:18:6b:de:a3:6e p2p_dev_addr=00:18:6b:de:a3:6e
 * pri_dev_type=1-0050F204-1 name='example p2p device' config_methods=0x188
 * dev_capb=0x25 group_capab=0x9
 * wfd_dev_info=0x000000000000 */
static void DealP2pFindInfo(char *buf)
{
    if (buf == NULL || strlen(buf) < WIFI_MAC_LENGTH) {
        return;
    }
    P2pDeviceInfo info = {0};
    if (strncpy_s(info.srcAddress, sizeof(info.srcAddress), buf, WIFI_MAC_LENGTH) != EOK) {
        return;
    }
    buf += WIFI_MAC_LENGTH + 1;
    char *savedPtr = NULL;
    char *s = strtok_r(buf, " ", &savedPtr);
    while (s != NULL) {
        WpaKeyValue retMsg = INIT_WPA_KEY_VALUE;
        GetStrKeyVal(s, "=", &retMsg);
        if (strncmp(retMsg.key, "p2p_dev_addr", strlen("p2p_dev_addr")) == 0) {
            StrSafeCopy(info.p2pDeviceAddress, sizeof(info.p2pDeviceAddress), retMsg.value);
        } else if (strncmp(retMsg.key, "pri_dev_type", strlen("pri_dev_type")) == 0) {
            StrSafeCopy(info.primaryDeviceType, sizeof(info.primaryDeviceType), retMsg.value);
        } else if (strncmp(retMsg.key, "config_methods", strlen("config_methods")) == 0) {
            info.configMethods = Hex2Dec(retMsg.value);
        } else if (strncmp(retMsg.key, "dev_capab", strlen("dev_capab")) == 0) {
            info.deviceCapabilities = Hex2Dec(retMsg.value);
        } else if (strncmp(retMsg.key, "group_capab", strlen("group_capab")) == 0) {
            info.groupCapabilities = Hex2Dec(retMsg.value);
        } else if (strncmp(retMsg.key, "wfd_dev_info", strlen("wfd_dev_info")) == 0) {
            if (strlen(retMsg.value) != strlen("0x000000000000")) {
                LOGD("Unexpected wfd device info, it's return 6 uint8 array convert to hex string!");
            } else {
                StrSafeCopy(info.wfdDeviceInfo, sizeof(info.wfdDeviceInfo), retMsg.value);
                info.wfdLength = strlen(info.wfdDeviceInfo);
            }
        } else if (strncmp(retMsg.key, "name", strlen("name")) == 0) {
            unsigned len = strlen(retMsg.value);
            if (len == SSID_EMPTY_LENGTH || (len < sizeof(retMsg.value) - 1 && retMsg.value[len - 1] != '\'')) {
                /* special deal: name='xxx xxx' || '   xxx' */
                s = strtok_r(NULL, "\'", &savedPtr);
                retMsg.value[len++] = ' ';
                StrSafeCopy(retMsg.value + len, sizeof(retMsg.value) - len, s);
            } /* can not deal with name='  x\'  x'*/
            TrimQuotationMark(retMsg.value, '\'');
            StrSafeCopy(info.deviceName, sizeof(info.deviceName), retMsg.value);
        }
        s = strtok_r(NULL, " ", &savedPtr);
    }
    P2pHalCbDeviceFound(&info);
    return;
}

static void DealP2pGoNegRequest(const char *buf)
{
    if (buf == NULL) {
        return;
    }
    char macAddr[WIFI_MAC_LENGTH + 1] = {0};
    if (strncpy_s(macAddr, sizeof(macAddr), buf, WIFI_MAC_LENGTH) != EOK) {
        return;
    }
    const char *passId = strstr(buf, "dev_passwd_id=");
    if (passId == NULL) {
        LOGD("Not find dev_passwd_id");
        return;
    }
    short passwordId = atoi(passId + strlen("dev_passwd_id="));
    P2pHalCbGoNegotiationRequest(macAddr, passwordId);
    return;
}

static void DealGroupStartInfo(char *buf)
{
    if (buf == NULL) {
        return;
    }
    P2pGroupInfo conf = {0};
    if (memset_s(&conf, sizeof(conf), 0, sizeof(conf)) != EOK) {
        return;
    }
    if (strstr(buf, "[PERSISTENT]") != NULL) {
        conf.isPersistent = 1;
    }

    char *savedPtr = NULL;
    char *token = strtok_r(buf, " ", &savedPtr);
    while (token != NULL) {
        WpaKeyValue retMsg = INIT_WPA_KEY_VALUE;
        GetStrKeyVal(token, "=", &retMsg);
        if (strncmp(retMsg.key, "GO", strlen("GO")) == 0) {
            conf.isGo = 1;
        } else if (strncmp(retMsg.key, "freq", strlen("freq")) == 0) {
            conf.frequency = atoi(retMsg.value);
        } else if (strncmp(retMsg.key, "go_dev_addr", strlen("go_dev_addr")) == 0) {
            StrSafeCopy(conf.goDeviceAddress, sizeof(conf.goDeviceAddress), retMsg.value);
        } else if (strncmp(retMsg.key, "p2p-", strlen("p2p-")) == 0) {
            StrSafeCopy(conf.groupIfName, sizeof(conf.groupIfName), retMsg.key);
        } else if (strncmp(retMsg.key, "psk", strlen("psk")) == 0) {
            StrSafeCopy(conf.psk, sizeof(conf.psk), retMsg.value);
        } else if (strncmp(retMsg.key, "ssid", strlen("ssid")) == 0 ||
                   strncmp(retMsg.key, "passphrase", strlen("passphrase")) == 0) {
            TrimQuotationMark(retMsg.value, '\"');
            if (strncmp(retMsg.key, "ssid", strlen("ssid")) == 0) {
                StrSafeCopy(conf.ssid, sizeof(conf.ssid), retMsg.value);
                PrintfDecode((u8 *)conf.ssid, sizeof(conf.ssid), conf.ssid);
            } else {
                StrSafeCopy(conf.passphrase, sizeof(conf.passphrase), retMsg.value);
            }
        }
        token = strtok_r(NULL, " ", &savedPtr);
    }
    P2pHalCbGroupStarted(&conf);
    return;
}

static void DealServiceDiscRespEvent(char *buf)
{
    if (buf == NULL) {
        return;
    }
    P2pServDiscRespInfo info = {0};
    if (memset_s(&info, sizeof(info), 0, sizeof(info)) != EOK) {
        return;
    }
    char *savedPtr = NULL;
    char *token = strtok_r(buf, " ", &savedPtr);
    int index = 0;
    while (token != NULL) {
        if (index == P2P_SERVICE_INFO_FIRST_SECTION) {
            if (strncpy_s(info.srcAddress, sizeof(info.srcAddress), token, strlen(token)) != EOK) {
                free(info.tlvs);
                info.tlvs = NULL;
                return;
            }
        } else if (index == P2P_SERVICE_INFO_SECOND_SECTION) {
            info.updateIndicator = atoi(token);
        } else if (index == P2P_SERVICE_INFO_THIRD_SECTION) {
            unsigned len = strlen(token) + 1;
            if (info.tlvs != NULL || len > WPA_CMD_BUF_LEN) {
                free(info.tlvs);
                info.tlvs = NULL;
            }
            info.tlvs = (char *)calloc(len, sizeof(char));
            if (info.tlvs == NULL || strncpy_s(info.tlvs, len, token, len - 1) != EOK) {
                free(info.tlvs);
                info.tlvs = NULL;
                return;
            }
        }
        index++;
        token = strtok_r(NULL, " ", &savedPtr);
    }
    P2pHalCbServiceDiscoveryResponse(&info);
    free(info.tlvs);
    info.tlvs = NULL;
    return;
}

static void DealP2pGroupRemove(const char *buf)
{
    if (buf == NULL) {
        return;
    }
    char groupIfname[WIFI_P2P_GROUP_IFNAME_LENGTH + 1] = {0};
    const char *pos = strstr(buf, " ");
    if (pos == NULL || pos - buf > WIFI_P2P_GROUP_IFNAME_LENGTH) {
        LOGD("pos is %{public}s", ((pos == NULL) ? "NULL" : "bigger than ifname length"));
        return;
    }
    if (strncpy_s(groupIfname, sizeof(groupIfname), buf, pos - buf) != EOK) {
        return;
    }
    int flag = 0;
    if (strstr(buf, "GO") != NULL) {
        flag = 1;
    }
    P2pHalCbGroupRemoved(groupIfname, flag);
    ReleaseWpaP2pGroupInterface(groupIfname); /* remove group interface */
    return;
}

static void DealP2pConnectChanged(const char *buf, int type)
{
    if (buf == NULL) {
        return;
    }
    char devAddr[WIFI_MAC_LENGTH + 1] = {0};
    const char *pos = strstr(buf, "p2p_dev_addr=");
    if (pos == NULL) {
        return;
    }
    if (strncpy_s(devAddr, sizeof(devAddr), pos + strlen("p2p_dev_addr="), WIFI_MAC_LENGTH) != EOK) {
        return;
    }
    char groupAddr[WIFI_MAC_LENGTH + 1] = {0};
    if (strncpy_s(groupAddr, sizeof(groupAddr), buf, WIFI_MAC_LENGTH) != EOK) {
        return;
    }
    P2pHalCbStaConnectState(devAddr, groupAddr, type);
    return;
}

static void DealDeviceLostEvent(const char *buf)
{
    if (buf == NULL) {
        return;
    }
    const char *peeraddr = strstr(buf, "p2p_dev_addr=");
    if (peeraddr == NULL) {
        return;
    }
    peeraddr += strlen("p2p_dev_addr=");
    char macAddr[WIFI_MAC_LENGTH + 1] = {0};
    if (strncpy_s(macAddr, sizeof(macAddr), peeraddr, WIFI_MAC_LENGTH) != EOK) {
        return;
    }
    P2pHalCbDeviceLost(macAddr);
    return;
}

static void DealInvitationReceived(char *buf, int type)
{
    if (buf == NULL) {
        return;
    }
    P2pInvitationInfo info = {0};
    if (memset_s(&info, sizeof(info), 0, sizeof(info)) != EOK) {
        return;
    }
    info.type = type;
    char *savedPtr = NULL;
    char *token = strtok_r(buf, " ", &savedPtr);
    while (token != NULL) {
        WpaKeyValue retMsg = INIT_WPA_KEY_VALUE;
        GetStrKeyVal(token, "=", &retMsg);
        if (strncmp(retMsg.key, "sa", strlen("sa")) == 0) {
            StrSafeCopy(info.srcAddress, sizeof(info.srcAddress), retMsg.value);
        } else if (strncmp(retMsg.key, "persistent", strlen("persistent")) == 0) {
            info.persistentNetworkId = atoi(retMsg.value);
        } else if (strncmp(retMsg.key, "freq", strlen("freq")) == 0) {
            info.operatingFrequency = atoi(retMsg.value);
        } else if (strncmp(retMsg.key, "go_dev_addr", strlen("go_dev_addr")) == 0) {
            StrSafeCopy(info.goDeviceAddress, sizeof(info.goDeviceAddress), retMsg.value);
        } else if (strncmp(retMsg.key, "bssid", strlen("bssid")) == 0) {
            StrSafeCopy(info.bssid, sizeof(info.bssid), retMsg.value);
        }
        token = strtok_r(NULL, " ", &savedPtr);
    }
    P2pHalCbInvitationReceived(&info);
    return;
}

static void DealInvitationResultEvent(const char *buf)
{
    if (buf == NULL) {
        return;
    }
    const char *sta = strstr(buf, "status=");
    if (sta == NULL) {
        return;
    }
    int status = atoi(sta + strlen("status="));
    const char *bssidpos = strstr(sta, " ");
    if (bssidpos == NULL) {
        return;
    }
    char macAddr[WIFI_MAC_LENGTH + 1] = {0};
    if (strncpy_s(macAddr, sizeof(macAddr), bssidpos + 1, WIFI_MAC_LENGTH) != EOK) {
        return;
    }
    P2pHalCbInvitationResult(macAddr, status);
    return;
}

static void DealP2pGoNegotiationFailure(const char *buf)
{
    if (buf == NULL) {
        return;
    }
    const char *sta = strstr(buf, "status=");
    if (sta == NULL) {
        return;
    }
    int status = atoi(sta + strlen("status="));
    P2pHalCbGoNegotiationFailure(status);
    return;
}

static void DealP2pConnectFailed(const char *buf)
{
    if (buf == NULL) {
        return;
    }
    const char *bssidPos = strstr(buf, "bssid=");
    if (bssidPos == NULL) {
        LOGE("bssidPos is null!");
        return;
    }
    bssidPos += strlen("bssid=");
    char macAddr[WIFI_MAC_LENGTH + 1] = {0};
    if (strncpy_s(macAddr, sizeof(macAddr), bssidPos, WIFI_MAC_LENGTH) != EOK) {
        LOGE("strncpy_s failed!");
        return;
    }
    const char *reaPos = strstr(buf, "reason=");
    if (reaPos == NULL) {
        LOGE("reaPos is null!");
        return;
    }
    int reason = atoi(reaPos + strlen("reason="));
    P2pHalCbP2pConnectFailed(macAddr, reason);
    return;
}

static void DealP2pChannelSwitch(const char *buf)
{
    if (buf == NULL) {
        return;
    }
    if (strstr(buf, "dfs=") != NULL) {
        LOGE("return ap channel switch!");
        return;
    }
    const char *freqPos = strstr(buf, "freq=");
    if (freqPos == NULL) {
        LOGE("freqPos is null!");
        return;
    }
    int freq = atoi(freqPos + strlen("freq="));
    LOGI("DealP2pChannelSwitch freq=%{public}d", freq);
    P2pHalCbP2pChannelSwitch(freq);
    return;
}

static void DealGroupFormationFailureEvent(const char *buf)
{
    if (buf == NULL) {
        return;
    }
    char reason[WIFI_P2P_GROUP_IFNAME_LENGTH + 1] = {0};
    char *reapos = strstr(buf, "reason=");
    if (reapos != NULL) {
        if (strncpy_s(reason, sizeof(reason), reapos + strlen("reason="), WIFI_P2P_GROUP_IFNAME_LENGTH) != EOK) {
            return;
        }
    }
    P2pHalCbGroupFormationFailure(reason);
    return;
}

static void DealProvDiscPbcReqEvent(const char *buf, unsigned long length)
{
    if (buf == NULL || length < strlen(P2P_EVENT_PROV_DISC_PBC_REQ) + WIFI_MAC_LENGTH) {
        return;
    }
    char macAddr[WIFI_MAC_LENGTH + 1] = {0};
    const char *pos = buf + strlen(P2P_EVENT_PROV_DISC_PBC_REQ);
    if (strncpy_s(macAddr, sizeof(macAddr), pos, WIFI_MAC_LENGTH) != EOK) {
        return;
    }
    P2pHalCbProvisionDiscoveryPbcRequest(macAddr);
    return;
}

static void DealProDiscPbcRespEvent(const char *buf, unsigned long length)
{
    if (buf == NULL || length < strlen(P2P_EVENT_PROV_DISC_PBC_RESP) + WIFI_MAC_LENGTH) {
        return;
    }
    char macAddr[WIFI_MAC_LENGTH + 1] = {0};
    const char *pos = buf + strlen(P2P_EVENT_PROV_DISC_PBC_RESP);
    if (strncpy_s(macAddr, sizeof(macAddr), pos, WIFI_MAC_LENGTH) != EOK) {
        return;
    }
    P2pHalCbProvisionDiscoveryPbcResponse(macAddr);
    return;
}

static void DealProDiscEnterPinEvent(const char *buf, unsigned long length)
{
    if (buf == NULL || length < strlen(P2P_EVENT_PROV_DISC_ENTER_PIN) + WIFI_MAC_LENGTH) {
        return;
    }
    char macAddr[WIFI_MAC_LENGTH + 1] = {0};
    const char *pos = buf + strlen(P2P_EVENT_PROV_DISC_ENTER_PIN);
    if (strncpy_s(macAddr, sizeof(macAddr), pos, WIFI_MAC_LENGTH) != EOK) {
        return;
    }
    P2pHalCbProvisionDiscoveryEnterPin(macAddr);
    return;
}

static void DealProvDiscShowPinEvent(const char *buf, unsigned long length)
{
    if (buf == NULL || length < strlen(P2P_EVENT_PROV_DISC_SHOW_PIN) + WIFI_MAC_LENGTH + 1 + WIFI_PIN_CODE_LENGTH) {
        return;
    }
    const char *p = buf + strlen(P2P_EVENT_PROV_DISC_SHOW_PIN);
    char macAddr[WIFI_MAC_LENGTH + 1] = {0};
    char pinCode[WIFI_PIN_CODE_LENGTH + 1] = {0};
    if (strncpy_s(macAddr, sizeof(macAddr), p, WIFI_MAC_LENGTH) != EOK) {
        return;
    }
    p += WIFI_MAC_LENGTH + 1;
    if (strncpy_s(pinCode, sizeof(pinCode), p, WIFI_PIN_CODE_LENGTH) != EOK) {
        return;
    }
    P2pHalCbProvisionDiscoveryShowPin(macAddr, pinCode);
    return;
}

static void DealP2pServDiscReqEvent(char *buf)
{
    if (buf == NULL) {
        return;
    }
    P2pServDiscReqInfo info;
    if (memset_s(&info, sizeof(info), 0, sizeof(info)) != EOK) {
        return;
    }
    char *savedPtr = NULL;
    char *token = strtok_r(buf, " ", &savedPtr);
    int index = 0;
    while (token != NULL && index <= P2P_SERVICE_DISC_REQ_FIVE) {
        if (index == P2P_SERVICE_DISC_REQ_ONE) {
            info.freq = atoi(token);
        } else if (index == P2P_SERVICE_DISC_REQ_TWO) {
            if (strncpy_s(info.mac, sizeof(info.mac), token, strlen(token)) != EOK) {
                free(info.tlvs);
                info.tlvs = NULL;
                return;
            }
        } else if (index == P2P_SERVICE_DISC_REQ_THREE) {
            info.dialogToken = atoi(token);
        } else if (index == P2P_SERVICE_DISC_REQ_FOUR) {
            info.updateIndic = atoi(token);
        } else if (index == P2P_SERVICE_DISC_REQ_FIVE) {
            unsigned len = strlen(token) + 1;
            if (info.tlvs != NULL || len > WPA_CMD_BUF_LEN) {
                free(info.tlvs);
                info.tlvs = NULL;
            }
            info.tlvs = (char *)calloc(len, sizeof(char));
            if (info.tlvs == NULL || strncpy_s(info.tlvs, len, token, len - 1) != EOK) {
                free(info.tlvs);
                info.tlvs = NULL;
                return;
            }
        }
        token = strtok_r(NULL, " ", &savedPtr);
        index++;
    }
    P2pHalCbServDiscReq(&info);
    free(info.tlvs);
    info.tlvs = NULL;
    return;
}

static void DealP2pInterfaceCreated(const char *buf)
{
    int type;
    char ifName[WIFI_IFACE_NAME_MAXLEN] = {0};
    if (strncmp(buf, "GO ", strlen("GO ")) == 0) {
        type = 1;
    } else if (strncmp(buf, "GC ", strlen("GC ")) == 0) {
        type = 0;
    } else {
        LOGE("p2p interface created invalid msg %{public}s", buf);
        return;
    }

    const char *pos = buf + strlen("GO "); // GO and GC have same length
    if (strlen(pos) >= WIFI_IFACE_NAME_MAXLEN || strlen(pos) == 0) {
        LOGE("p2p interface created invalid ifname len %{public}zu", strlen(pos));
        return;
    }
    if (strncpy_s(ifName, sizeof(ifName), pos, strlen(pos)) != EOK) {
        return;
    }
    P2pHalCbP2pIfaceCreated(ifName, type);
}

static int DealWpaP2pCallBackSubFun(char *p)
{
    if (p == NULL) {
        return -1;
    }
    if (strncmp(p, P2P_EVENT_DEVICE_FOUND, strlen(P2P_EVENT_DEVICE_FOUND)) == 0) {
        DealP2pFindInfo(p + strlen(P2P_EVENT_DEVICE_FOUND));
    } else if (strncmp(p, P2P_EVENT_DEVICE_LOST, strlen(P2P_EVENT_DEVICE_LOST)) == 0) {
        DealDeviceLostEvent(p);
    } else if (strncmp(p, P2P_EVENT_GO_NEG_REQUEST, strlen(P2P_EVENT_GO_NEG_REQUEST)) == 0) {
        DealP2pGoNegRequest(p + strlen(P2P_EVENT_GO_NEG_REQUEST));
    } else if (strncmp(p, P2P_EVENT_GO_NEG_SUCCESS, strlen(P2P_EVENT_GO_NEG_SUCCESS)) == 0) {
        P2pHalCbGoNegotiationSuccess();
    } else if (strncmp(p, P2P_EVENT_GO_NEG_FAILURE, strlen(P2P_EVENT_GO_NEG_FAILURE)) == 0) {
        DealP2pGoNegotiationFailure(p);
    } else if (strncmp(p, P2P_EVENT_INVITATION_RECEIVED, strlen(P2P_EVENT_INVITATION_RECEIVED)) == 0) {
        DealInvitationReceived(p, 0);
    } else if (strncmp(p, P2P_EVENT_INVITATION_ACCEPTED, strlen(P2P_EVENT_INVITATION_ACCEPTED)) == 0) {
        DealInvitationReceived(p, 1);
    } else if (strncmp(p, P2P_EVENT_INVITATION_RESULT, strlen(P2P_EVENT_INVITATION_RESULT)) == 0) {
        DealInvitationResultEvent(p);
    } else if (strncmp(p, P2P_EVENT_GROUP_FORMATION_SUCCESS, strlen(P2P_EVENT_GROUP_FORMATION_SUCCESS)) == 0) {
        P2pHalCbGroupFormationSuccess();
    } else if (strncmp(p, P2P_EVENT_GROUP_FORMATION_FAILURE, strlen(P2P_EVENT_GROUP_FORMATION_FAILURE)) == 0) {
        DealGroupFormationFailureEvent(p);
    } else if (strncmp(p, P2P_EVENT_GROUP_STARTED, strlen(P2P_EVENT_GROUP_STARTED)) == 0) {
        DealGroupStartInfo(p);
    } else if (strncmp(p, P2P_EVENT_GROUP_REMOVED, strlen(P2P_EVENT_GROUP_REMOVED)) == 0) {
        DealP2pGroupRemove(p + strlen(P2P_EVENT_GROUP_REMOVED));
    } else if (strncmp(p, P2P_INTERFACE_CREATED, strlen(P2P_INTERFACE_CREATED)) == 0) {
        DealP2pInterfaceCreated(p + strlen(P2P_INTERFACE_CREATED));
    } else if (strncmp(p, CTRL_EVENT_DISCONNECTED, strlen(CTRL_EVENT_DISCONNECTED)) == 0) {
        DealP2pConnectFailed(p);
    } else if (strncmp(p, CTRL_EVENT_CHANNEL_SWITCH, strlen(CTRL_EVENT_CHANNEL_SWITCH)) == 0) {
        DealP2pChannelSwitch(p);
    } else {
        return 1;
    }
    return 0;
}

static int WpaP2pCallBackFunc(char *p)
{
    if (p == NULL) {
        LOGI("recv notify message is NULL");
        return -1;
    }
    LOGD("wpa p2p callback p :%{private}s!", p);
    if (strncmp(p, P2P_EVENT_PROV_DISC_PBC_REQ, strlen(P2P_EVENT_PROV_DISC_PBC_REQ)) == 0) {
        DealProvDiscPbcReqEvent(p, strlen(p));
    } else if (strncmp(p, P2P_EVENT_PROV_DISC_PBC_RESP, strlen(P2P_EVENT_PROV_DISC_PBC_RESP)) == 0) {
        DealProDiscPbcRespEvent(p, strlen(p));
    } else if (strncmp(p, P2P_EVENT_PROV_DISC_ENTER_PIN, strlen(P2P_EVENT_PROV_DISC_ENTER_PIN)) == 0) {
        DealProDiscEnterPinEvent(p, strlen(p));
    } else if (strncmp(p, P2P_EVENT_PROV_DISC_SHOW_PIN, strlen(P2P_EVENT_PROV_DISC_SHOW_PIN)) == 0) {
        DealProvDiscShowPinEvent(p, strlen(p));
    } else if (strncmp(p, P2P_EVENT_FIND_STOPPED, strlen(P2P_EVENT_FIND_STOPPED)) == 0) {
        P2pHalCbFindStopped();
    } else if (strncmp(p, P2P_EVENT_SERV_DISC_RESP, strlen(P2P_EVENT_SERV_DISC_RESP)) == 0) {
        DealServiceDiscRespEvent(p);
    } else if (strncmp(p, P2P_EVENT_PROV_DISC_FAILURE, strlen(P2P_EVENT_PROV_DISC_FAILURE)) == 0) {
        P2pHalCbProvisionDiscoveryFailure();
    } else if (strncmp(p, AP_STA_DISCONNECTED, strlen(AP_STA_DISCONNECTED)) == 0) {
        DealP2pConnectChanged(p + strlen(AP_STA_DISCONNECTED), 0);
    } else if (strncmp(p, AP_STA_CONNECTED, strlen(AP_STA_CONNECTED)) == 0) {
        DealP2pConnectChanged(p + strlen(AP_STA_CONNECTED), 1);
    } else if (strncmp(p, P2P_EVENT_SERV_DISC_REQ, strlen(P2P_EVENT_SERV_DISC_REQ)) == 0) {
        DealP2pServDiscReqEvent(p);
    } else {
        if (DealWpaP2pCallBackSubFun(p) != 0) {
            return 1;
        }
    }
    return 0;
}
static void ParseAuthReject(const char *p)
{
    char *connectionStatus = strstr(p, "status_code=");
    if (connectionStatus != NULL) {
        connectionStatus += strlen("status_code=");
        int status = atoi(connectionStatus);
        if (status == CONNECTION_PWD_WRONG_STATUS) {
            WifiHalCbNotifyWrongKey(1);
        } else if (status == CONNECTION_FULL_STATUS) {
            WifiHalCbNotifyConnectionFull(status);
        } else if (status == CONNECTION_REJECT_STATUS ||
            status == WLAN_STATUS_AUTH_TIMEOUT ||
            status == MAC_AUTH_RSP2_TIMEOUT ||
            status == MAC_AUTH_RSP4_TIMEOUT ||
            status == MAC_ASSOC_RSP_TIMEOUT) {
            WifiHalCbNotifyConnectionReject(status);
        }
    }
}

static void ParseAssocReject(const char *p)
{
    char *connectionStatus = strstr(p, "status_code=");
    if (connectionStatus != NULL) {
        connectionStatus += strlen("status_code=");
        int status = atoi(connectionStatus);
        if (status == CONNECTION_FULL_STATUS) {
            WifiHalCbNotifyConnectionFull(status);
        } else if (status == CONNECTION_REJECT_STATUS ||
            status == WLAN_STATUS_AUTH_TIMEOUT ||
            status == MAC_AUTH_RSP2_TIMEOUT ||
            status == MAC_AUTH_RSP4_TIMEOUT ||
            status == MAC_ASSOC_RSP_TIMEOUT ||
            status == CONNECTION_PWD_WRONG_STATUS) {
            WifiHalCbNotifyConnectionReject(status);
        }
    }
}

static void WpaCallBackFuncTwo(const char *p)
{
    if (p == NULL) {
        LOGI("recv notify message is NULL");
        return;
    }
    if (strncmp(p, WPA_EVENT_STATE_CHANGE, strlen(WPA_EVENT_STATE_CHANGE)) == 0) { /* wpa-state change */
        char *pstate = strstr(p, "state=");
        if (pstate != NULL) {
            pstate += strlen("state=");
            WifiHalCbNotifyWpaStateChange(atoi(pstate));
        }
    } else if (strncmp(p, WPA_EVENT_TEMP_DISABLED, strlen(WPA_EVENT_TEMP_DISABLED)) == 0) { /* Wrong Key */
        if (strstr(p, "reason=WRONG_KEY") != NULL || strstr(p, "reason=AUTH_FAILED") != NULL) {
            WifiHalCbNotifyWrongKey(1);
        }
    } else if (strncmp(p, WPS_EVENT_PBC_OVERLAP, strlen(WPS_EVENT_PBC_OVERLAP)) == 0) { /* wps_pbc_overlap */
        WifiHalCbNotifyWpsOverlap(1);
    } else if (strncmp(p, WPS_EVENT_TIMEOUT, strlen(WPS_EVENT_TIMEOUT)) == 0) {
        WifiHalCbNotifyWpsTimeOut(1);
    } else if (strncmp(p, WPA_EVENT_AUTH_REJECT, strlen(WPA_EVENT_AUTH_REJECT)) == 0) { /* connection full */
        ParseAuthReject(p);
    } else if (strncmp(p, WPA_EVENT_ASSOC_REJECT, strlen(WPA_EVENT_ASSOC_REJECT)) == 0) {
        ParseAssocReject(p);
    } else if (strncmp(p, WPA_EVENT_ASSOCIATING, strlen(WPA_EVENT_ASSOCIATING)) == 0) {
        char *pBssid = strstr(p, WPA_EVENT_ASSOCIATING);
        if (pBssid == NULL) {
            return;
        }
        pBssid += strlen(WPA_EVENT_ASSOCIATING);
        WifiHalCbNotifyConnectChanged(WPA_CB_ASSOCIATING, -1, pBssid);
    } else if (strncmp(p, WPA_EVENT_ASSOCIATED, strlen(WPA_EVENT_ASSOCIATED)) == 0) {
        char *pBssid = strstr(p, WPA_EVENT_ASSOCIATED);
        if (pBssid == NULL) {
            return;
        }
        pBssid += strlen(WPA_EVENT_ASSOCIATED);
        WifiHalCbNotifyConnectChanged(WPA_CB_ASSOCIATED, -1, pBssid);
    }
    return;
}

static void WpaCallBackFunc(const char *p)
{
    if (p == NULL) {
        LOGI("recv notify message is NULL");
        return;
    }
    if (strncmp(p, WPA_EVENT_SCAN_RESULTS, strlen(WPA_EVENT_SCAN_RESULTS)) == 0) {
        WifiHalCbNotifyScanEnd(STA_CB_SCAN_OVER_OK);
    } else if (strncmp(p, WPA_EVENT_SCAN_FAILED, strlen(WPA_EVENT_SCAN_FAILED)) == 0) {
        WifiHalCbNotifyScanEnd(STA_CB_SCAN_FAILED);
    } else if (strncmp(p, WPA_EVENT_CONNECTED, strlen(WPA_EVENT_CONNECTED)) == 0) { /* Connection notification */
        char *pid = strstr(p, "id=");
        char *pMacPos = strstr(p, "Connection to ");
        if (pid == NULL || pMacPos == NULL) {
            return;
        }
        pid += strlen("id=");
        pMacPos += strlen("Connection to ");
        int id = atoi(pid);
        if (id < 0) {
            id = -1;
        }
        WifiHalCbNotifyConnectChanged(WPA_CB_CONNECTED, id, pMacPos);
    } else if (strncmp(p, WPA_EVENT_DISCONNECTED, strlen(WPA_EVENT_DISCONNECTED)) == 0) { /* Disconnection */
        char *pBssid = strstr(p, "bssid=");
        if (pBssid == NULL) {
            return;
        }
        pBssid += strlen("bssid=");
        char *reasonPos = strstr(p, "reason=");
        int reasonCode = -1;
        if (reasonPos != NULL) {
            reasonPos += strlen("reason=");
            int ret = sscanf_s(reasonPos, "%d", &reasonCode);
            if (ret < 0) {
                LOGE("reasonCode failed!");
                return;
            }
        }
        WifiHalCbNotifyDisConnectReason(reasonCode, pBssid);
        WifiHalCbNotifyConnectChanged(WPA_CB_DISCONNECTED, reasonCode, pBssid);
    /* bssid changed event */
    } else if (strncmp(p, WPA_EVENT_BSSID_CHANGED, strlen(WPA_EVENT_BSSID_CHANGED)) == 0) {
        LOGI("Reveive WPA_EVENT_BSSID_CHANGED notify event");
        char *pBssid = strstr(p, "BSSID=");
        if (pBssid == NULL) {
            LOGE("NO bssid find!");
            return;
        }
        pBssid += strlen("BSSID=");
        char *pReason = strstr(p, "REASON=");
        if (pReason == NULL) {
            LOGE("NO reason find!");
            return;
        }
        pReason += strlen("REASON=");
        WifiHalCbNotifyBssidChanged(pReason, pBssid);
    } else {
        WpaCallBackFuncTwo(p);
    }
}

static int MyWpaCtrlPending(struct wpa_ctrl *ctrl)
{
    if (ctrl == NULL) {
        return -1;
    }
    struct pollfd pfd;
    if (memset_s(&pfd, sizeof(pfd), 0, sizeof(pfd)) != EOK) {
        return -1;
    }
    pfd.fd = wpa_ctrl_get_fd(ctrl);
    pfd.events = POLLIN;
    int ret = poll(&pfd, 1, 100); /* 100 ms */
    if (ret < 0) {
        LOGE("poll failed! errno = %{public}d", errno);
        if (errno == EINTR) {
            return 0;
        }
        return -1;
    }
    if (ret == 0) {
        return 0;
    }
    return 1;
}

static void StopWpaSuppilicant(ModuleInfo *p)
{
    if (p == NULL) {
        return;
    }
    LOGI("p->referenceCount = %{public}d.", p->referenceCount);
    if (p->referenceCount > 1) {
        if (P2pStop() != WIFI_HAL_SUCCESS) {
            LOGE("P2p stop failed.");
        }
        if (Stop() != WIFI_HAL_SUCCESS) {
            LOGE("Sta stop failed.");
        }
    } else {
        if (Stop() != WIFI_HAL_SUCCESS) {
            LOGE("Sta stop failed.");
        }
    }
}

static void StopWpaSoftAp(ModuleInfo *p)
{
    if (p == NULL) {
        return;
    }

    int apCount = p->referenceCount;
    int stopCount = 0;
    while (stopCount < apCount) {
        if (StopSoftAp(stopCount) != WIFI_HAL_SUCCESS) {
            LOGE("Ap instance %{public}d stop failed.", stopCount);
        }
        stopCount += 1;
    }
}

static void *RecoverWifiProcess(void *arg)
{
    ModuleInfo *p = NULL;
    p = GetStartedModule();
    if (p == NULL) {
        LOGI("No wpa process need to recover.");
        return NULL;
    }

    if (strcmp(p->szModuleName, WPA_SUPPLICANT_NAME) == 0) {
        StopWpaSuppilicant(p);
    } else if (strcmp(p->szModuleName, WPA_HOSTAPD_NAME) == 0) {
        StopWpaSoftAp(p);
    }

    exit(0);
    return NULL;
}

static void RecoverWifiThread(void)
{
    LOGI("wpa process stoped, ready to recover it!");
    pthread_t tid;
    if (pthread_create(&tid, NULL, RecoverWifiProcess, NULL) != 0) {
        LOGE("create wpa restart thread failed!");
    }
    pthread_detach(tid);
}

static void *WpaReceiveCallback(void *arg)
{
    if (arg == NULL) {
        return NULL;
    }
    char staIface[] = "IFNAME=wlan";
    char p2pIface[] = "IFNAME=p2p";
    char chbaIface[] = "IFNAME=chba";
    WifiWpaInterface *pWpa = arg;
    char *buf = (char *)calloc(REPLY_BUF_LENGTH, sizeof(char));
    if (buf == NULL) {
        LOGE("In wpa deal receive message thread, failed to calloc buff!");
        return NULL;
    }
    while (pWpa->threadRunFlag) {
        int ret = MyWpaCtrlPending(pWpa->wpaCtrl.pRecv);
        if (ret < 0) {
            LOGE("thread get event message failed!");
            break;
        } else if (ret == 0) {
            continue;
        }
        if (memset_s(buf, REPLY_BUF_LENGTH, 0, REPLY_BUF_LENGTH) != EOK) {
            LOGE("thread clear buffer cache failed!");
            break;
        }
        size_t len = REPLY_BUF_LENGTH - 1;
        ret = wpa_ctrl_recv(pWpa->wpaCtrl.pRecv, buf, &len);
        if (ret < 0) {
            LOGE("thread read event message failed!");
            break;
        }
        if (len <= 0) {
            continue;
        }
        LOGD("wpa recv buf: %{public}s!", buf);
        /* Message format: IFNAME=wlan0 <priority>EventType params... */
        char *p = strchr(buf, '>');
        if (p == NULL) {
            p = buf;
        } else {
            p++;
        }
        if (strncmp(p, WPA_EVENT_TERMINATING, strlen(WPA_EVENT_TERMINATING)) == 0) {
            LOGI("=====================WPA_EVENT_TERMINATING=======================");
            RecoverWifiThread();
            break;
        }
        char *iface = strstr(buf, "IFNAME=");
        if (iface == NULL) {
            /* if 'IFNAME=' is not reported */
            if (strstr(p, "chba0") != NULL) {
                HalCallbackNotify(p);
                continue;
            }
            if (WpaP2pCallBackFunc(p) == 0) {
                continue;
            }
            WpaCallBackFunc(p);
            continue;
        }
        if (strncmp(iface, p2pIface, strlen(p2pIface)) == 0) {
            if (WpaP2pCallBackFunc(p) == 0) {
                continue;
            }
        }
        if (strncmp(iface, staIface, strlen(staIface)) == 0) {
            WpaCallBackFunc(p);
        }
        if (strncmp(iface, chbaIface, strlen(chbaIface)) == 0) {
            HalCallbackNotify(p);
        }
    }
    free(buf);
    buf = NULL;
    LOGI("=====================thread exit=======================");
    return NULL;
}

static int WpaCliConnect(WifiWpaInterface *p)
{
    LOGI("Wpa connect start.");
    if (p == NULL) {
        LOGE("Wpa connect parameter error.");
        return -1;
    }
    if (p->wpaCtrl.pSend != NULL) {
        LOGE("Wpa is already connected.");
        return 0;
    }
    int count = WPA_TRY_CONNECT_TIMES;
    while (count-- > 0) {
        int ret = InitWpaCtrl(&p->wpaCtrl, WPA_CTRL_OPEN_IFNAME);
        if (ret == 0) {
            LOGI("Global wpa interface connect successfully!");
            break;
        } else {
            LOGE("Init wpaCtrl failed: %{public}d", ret);
        }
        usleep(WPA_TRY_CONNECT_SLEEP_TIME);
    }
    if (count <= 0) {
        return -1;
    }
    p->threadRunFlag = 1;
    if (pthread_create(&p->tid, NULL, WpaReceiveCallback, p) != 0) {
        p->threadRunFlag = 0;
        ReleaseWpaCtrl(&p->wpaCtrl);
        LOGE("Create monitor thread failed!");
        return -1;
    }
    pthread_setname_np(p->tid, "WpaCBThread");
    LOGI("Wpa connect finish.");
    return 0;
}

static void WpaCliClose(WifiWpaInterface *p)
{
    if (p->tid != 0) {
        p->threadRunFlag = 0;
        pthread_join(p->tid, NULL);
        p->tid = 0;
    }
    ReleaseWpaCtrl(&p->wpaCtrl);
    return;
}

static int WpaCliAddIface(WifiWpaInterface *p, const AddInterfaceArgv *argv, bool isWpaAdd)
{
    if (p == NULL || argv == NULL) {
        return -1;
    }
    WpaIfaceInfo *info = p->ifaces;
    while (info != NULL) {
        if (strcmp(info->name, argv->name) == 0) {
            return 0;
        }
        info = info->next;
    }
    info = (WpaIfaceInfo *)calloc(1, sizeof(WpaIfaceInfo));
    if (info == NULL) {
        return -1;
    }
    StrSafeCopy(info->name, sizeof(info->name), argv->name);
    char cmd[WPA_CMD_BUF_LEN] = {0};
    char buf[WPA_CMD_REPLY_BUF_SMALL_LEN] = {0};
    LOGI("Add interface start.");
    if (isWpaAdd && (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "INTERFACE_ADD %s\t%s",
        argv->name, argv->confName) < 0 || WpaCliCmd(cmd, buf, sizeof(buf)) != 0)) {
        free(info);
        info = NULL;
        LOGI("WpaCliAddIface failed, cmd: %{public}s, buf: %{public}s", cmd, buf);
        return -1;
    }
    LOGI("Add interface finish, cmd: %{public}s, buf: %{public}s", cmd, buf);
    info->next = p->ifaces;
    p->ifaces = info;
    return 0;
}

static int WpaCliRemoveIface(WifiWpaInterface *p, const char *name)
{
    if (p == NULL || name == NULL) {
        return -1;
    }
    LOGI("Remove interface: %{public}s", name);
    WpaIfaceInfo *prev = NULL;
    WpaIfaceInfo *info = p->ifaces;
    while (info != NULL) {
        if (strcmp(info->name, name) == 0) {
            break;
        }
        prev = info;
        info = info->next;
    }
    if (info == NULL) {
        return 0;
    }
    char cmd[WPA_CMD_BUF_LEN] = {0};
    char buf[WPA_CMD_REPLY_BUF_SMALL_LEN] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "INTERFACE_REMOVE %s", name) < 0 ||
        WpaCliCmd(cmd, buf, sizeof(buf)) != 0) {
        return -1;
    }
    if (prev == NULL) {
        p->ifaces = info->next;
    } else {
        prev->next = info->next;
    }
    free(info);
    info = NULL;
    return 0;
}

static int WpaCliWpaTerminate(void)
{
    LOGI("Enter WpaCliWpaTerminate");
    char cmd[WPA_CMD_BUF_LEN] = {0};
    char buf[WPA_CMD_REPLY_BUF_SMALL_LEN] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "TERMINATE") < 0) {
        LOGE("WpaCliWpaTerminate, snprintf err");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

WifiWpaInterface *GetWifiWapGlobalInterface(void)
{
    if (g_wpaInterface != NULL) {
        return g_wpaInterface;
    }
    g_wpaInterface = (WifiWpaInterface *)calloc(1, sizeof(WifiWpaInterface));
    if (g_wpaInterface == NULL) {
        LOGE("Failed to create wpa interface!");
        return NULL;
    }
    g_wpaInterface->wpaCliConnect = WpaCliConnect;
    g_wpaInterface->wpaCliClose = WpaCliClose;
    g_wpaInterface->wpaCliAddIface = WpaCliAddIface;
    g_wpaInterface->wpaCliRemoveIface = WpaCliRemoveIface;
    g_wpaInterface->wpaCliTerminate = WpaCliWpaTerminate;
    return g_wpaInterface;
}

void ReleaseWpaGlobalInterface(void)
{
    if (g_wpaInterface == NULL) {
        return;
    }
    WpaIfaceInfo *p = g_wpaInterface->ifaces;
    while (p != NULL) {
        WpaIfaceInfo *q = p->next;
        free(p);
        p = q;
    }
    WpaCliClose(g_wpaInterface);
    free(g_wpaInterface);
    g_wpaInterface = NULL;
}

WpaCtrl *GetWpaCtrl(void)
{
    if (g_wpaInterface == NULL) {
        return NULL;
    }
    return &g_wpaInterface->wpaCtrl;
}
