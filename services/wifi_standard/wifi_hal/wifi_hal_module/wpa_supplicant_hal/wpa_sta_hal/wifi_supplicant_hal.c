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

#include "wifi_supplicant_hal.h"
#include <poll.h>
#include <pthread.h>
#include "wifi_hal_callback.h"
#include "securec.h"
#include "wifi_log.h"
#include "common/wpa_ctrl.h"
#include "wifi_hal_common_func.h"

#undef LOG_TAG
#define LOG_TAG "WifiWpaStaHal"

/*
 * Network interface name, which is hardcoded temporarily and
 * needs to be automatically created by the netlink interface.
 */
#define CONFIG_CTRL_IFACE_NAME "wlan0"

#define WPS_EVENT_PBC_OVERLAP "WPS-OVERLAP-DETECTED PBC session overlap"
WifiHalDevice *g_wpaHalDev = NULL;

#define CONN_ID_CK_LENG 3
#define STATUS_CK_LENG 6
#define FAIL_BUSY 2
#define SCAN_RESULT_NONE 0
#define SCAN_RESULT_ONE 1
#define SCAN_RESULT_TWO 2
#define SCAN_RESULT_THREE 3
#define FAIL_PBC_OVERLAP_RETUEN 3
#define SCAN_RESULT_EMPTY (-2)

#define CMD_BUFFER_SIZE 512
#define CMD_BUFFER_SMALL_SIZE 64

static WpaSsidField g_wpaSsidFields[] = {
    {DEVICE_CONFIG_SSID, "ssid", 0},
    {DEVICE_CONFIG_PSK, "psk", 0},
    {DEVICE_CONFIG_KEYMGMT, "key_mgmt", 1},
    {DEVICE_CONFIG_PRIORITY, "priority", 1},
    {DEVICE_CONFIG_SCAN_SSID, "scan_ssid", 1},
    {DEVICE_CONFIG_EAP, "eap", 1},
    {DEVICE_CONFIG_IDENTITY, "identity", 0},
    {DEVICE_CONFIG_PASSWORD, "password", 0},
    {DEVICE_CONFIG_BSSID, "bssid", 1},
    {DEVICE_CONFIG_AUTH_ALGORITHMS, "auth_alg", 1},
    {DEVICE_CONFIG_WEP_KEY_IDX, "wep_tx_keyidx", 1},
    {DEVICE_CONFIG_WEP_KEY_0, "wep_key0", 1},
    {DEVICE_CONFIG_WEP_KEY_1, "wep_key1", 1},
    {DEVICE_CONFIG_WEP_KEY_2, "wep_key2", 1},
    {DEVICE_CONFIG_WEP_KEY_3, "wep_key3", 1}
};

/**
 * The wpa_ctrl_pending interface provided by the WPA does not wait for the
 * response. As a result, the CPU usage is high. Reconstructed
 */
static int MyWpaCtrlPending(struct wpa_ctrl *ctrl)
{
    struct pollfd pfd;
    if (memset_s(&pfd, sizeof(pfd), 0, sizeof(pfd)) != EOK) {
        return -1;
    }
    pfd.fd = wpa_ctrl_get_fd(ctrl);
    pfd.events = POLLIN;
    int ret = poll(&pfd, 1, 100); /* 100 ms */
    if (ret < 0) {
        LOGE("poll failed!");
        return -1;
    }
    if (ret == 0) {
        return 0;
    }
    return 1;
}

static void WpaCallBackFuncTwo(const char *p, int ptrLen)
{
    if (ptrLen <= 0) {
        LOGI("recv notify message is NULL");
        return;
    }
    if (strncmp(p, WPA_EVENT_STATE_CHANGE, strlen(WPA_EVENT_STATE_CHANGE)) == 0) {
        /* wpa-state change */
        char *pstate = strstr(p, "state=");
        if (pstate != NULL) {
            int wpastate = (pstate[STATUS_CK_LENG] - '0');
            WifiHalCbNotifyWpaStateChange(wpastate);
        }
    } else if (strncmp(p, WPA_EVENT_TEMP_DISABLED, strlen(WPA_EVENT_TEMP_DISABLED)) == 0) {
        /* WrongKey */
        char *preason = strstr(p, "reason=WRONG_KEY");
        if (preason != NULL) {
            WifiHalCbNotifyWrongKey(1);
        }
    } else if (strncmp(p, WPS_EVENT_PBC_OVERLAP, strlen(WPS_EVENT_PBC_OVERLAP)) == 0) { /* wps_pbc_overlap */
        WifiHalCbNotifyWpsOverlap(1);
    } else if (strncmp(p, WPS_EVENT_TIMEOUT, strlen(WPS_EVENT_TIMEOUT)) == 0) { /* wps_pbc_overlap */
        WifiHalCbNotifyWpsTimeOut(1);
    } else {
        LOGI("recv other msg");
    }
    return;
}

static void WpaCallBackFunc(const char *p, int ptrLen)
{
    if (ptrLen <= 0) {
        LOGI("recv notify message is NULL");
        return;
    }
    if (strncmp(p, WPA_EVENT_SCAN_RESULTS, strlen(WPA_EVENT_SCAN_RESULTS)) == 0) {
        WifiHalCbNotifyScanEnd(WPA_CB_SCAN_OVER_OK);
    } else if (strncmp(p, WPA_EVENT_SCAN_FAILED, strlen(WPA_EVENT_SCAN_FAILED)) == 0) {
        WifiHalCbNotifyScanEnd(WPA_CB_SCAN_FAILED);
    } else if (strncmp(p, WPA_EVENT_CONNECTED, strlen(WPA_EVENT_CONNECTED)) == 0) {
        /* Connection notification */
        char *pid = strstr(p, "id=");
        char *pMacPos = strstr(p, "Connection to ");
        if (pid == NULL || pMacPos == NULL) {
            return;
        }
        pMacPos += strlen("Connection to ");
        int id = atoi(pid + CONN_ID_CK_LENG);
        if (id < 0) {
            id = -1;
        }
        WifiHalCbNotifyConnectChanged(WPA_CB_CONNECTED, id, pMacPos);
    } else if (strncmp(p, WPA_EVENT_DISCONNECTED, strlen(WPA_EVENT_DISCONNECTED)) == 0) {
        /* Disconnection notification */
        char *pBssid = strstr(p, "bssid=");
        if (pBssid == NULL) {
            return;
        }
        pBssid += strlen("bssid=");
        WifiHalCbNotifyConnectChanged(WPA_CB_DISCONNECTED, -1, pBssid);
    } else {
        WpaCallBackFuncTwo(p, strlen(p));
    }
    return;
}

static void *WpaReceiveCallback(void *arg)
{
    struct wpa_ctrl *ctrl = arg;
    char *buf = (char *)calloc(REPLY_BUF_LENGTH, sizeof(char));
    if (buf == NULL) {
        LOGE("In wpa deal receive message thread, failed to calloc buff!");
        return NULL;
    }
    while (g_wpaHalDev->threadRunFlag) {
        int ret = MyWpaCtrlPending(ctrl);
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
        ret = wpa_ctrl_recv(ctrl, buf, &len);
        if (ret < 0) {
            LOGE("thread read event message failed!");
            break;
        }
        if (len <= 0) {
            LOGE("thread read event message leng err!");
            continue;
        }
        /* Message format: <priority>EventType params... */
        char *p = buf;
        char *prev = buf;
        if (*p == '<') {
            prev = p;
            p = strchr(p, '>');
        }
        if (p != NULL) {
            p++;
        } else {
            p = prev;
        }
        if (strncmp(p, WPA_EVENT_TERMINATING, strlen(WPA_EVENT_TERMINATING)) == 0) {
            break;
        }
        WpaCallBackFunc(p, strlen(p));
    }
    free(buf);
    LOGI("=====================thread exist=======================");
    return NULL;
}

static int WifiWpaConnectSupported(void)
{
    int flag = 0;
    do {
        g_wpaHalDev->ctrlConn = wpa_ctrl_open(CONFIG_CTRL_IFACE_NAME);
        g_wpaHalDev->monConn = wpa_ctrl_open(CONFIG_CTRL_IFACE_NAME);
        if (g_wpaHalDev->ctrlConn == NULL || g_wpaHalDev->monConn == NULL) {
            LOGE("open wpa control interface failed!");
            break;
        }
        if (wpa_ctrl_attach(g_wpaHalDev->monConn) != 0) {
            LOGE("attach monitor interface failed!");
            break;
        }
        g_wpaHalDev->threadRunFlag = 1;
        if (pthread_create(&g_wpaHalDev->tid, NULL, WpaReceiveCallback, g_wpaHalDev->monConn) != 0) {
            wpa_ctrl_detach(g_wpaHalDev->monConn);
            LOGE("Create monitor thread failed!");
            break;
        }
        flag = 1;
    } while (0);
    if (!flag) {
        if (g_wpaHalDev->ctrlConn != NULL) {
            wpa_ctrl_close(g_wpaHalDev->ctrlConn);
            g_wpaHalDev->ctrlConn = NULL;
        }
        if (g_wpaHalDev->monConn != NULL) {
            wpa_ctrl_close(g_wpaHalDev->monConn);
            g_wpaHalDev->monConn = NULL;
        }
        return -1;
    }
    LOGI("WifiWpaCliConnectWpa: open wpa success!");
    return 0;
}

/*
 * Currently, the connection mode of the connection function is fixed. Need to
 * optimize the connection mode
 */
static int WifiWpaCliConnectWpa(void)
{
    if (g_wpaHalDev->ctrlConn != NULL) {
        return 0;
    }
    return WifiWpaConnectSupported();
}

static void WifiWpaCliWpaCtrlClose(void)
{
    if (g_wpaHalDev->ctrlConn != NULL) {
        g_wpaHalDev->threadRunFlag = 0;
        pthread_join(g_wpaHalDev->tid, NULL);
        g_wpaHalDev->tid = 0;
        wpa_ctrl_close(g_wpaHalDev->monConn);
        g_wpaHalDev->monConn = NULL;
        wpa_ctrl_close(g_wpaHalDev->ctrlConn);
        g_wpaHalDev->ctrlConn = NULL;
    }
}

/* ******************Command without parameters**************** */
/**
 * Command processing function
 * This function needs to be deleted during printing and delivery.
 */
static int WpaCliCmd(const char *cmd, char *buf, size_t bufLen)
{
    if (g_wpaHalDev->ctrlConn == NULL || bufLen <= 0) {
        LOGE("Request parameters not correct");
        return -1;
    }
    size_t len = bufLen - 1;
    int ret = wpa_ctrl_request(g_wpaHalDev->ctrlConn, cmd, strlen(cmd), buf, &len, NULL);
    if (ret == CMD_RTUEN_TIMEOUT) {
        LOGE("[%s] command timed out.", cmd);
        return CMD_RTUEN_TIMEOUT;
    } else if (ret < 0) {
        LOGE("[%s] command failed.", cmd);
        return -1;
    } else {
        buf[len] = '\0';
        LOGE("cmd = %s, buf :%s", cmd, buf);
    }
    return 0;
}

/* cmd :status：Checking the Wi-Fi Status */
static int WpaCliCmdStatus(struct WpaHalCmdStatus *pcmd)
{
    char *buf = (char *)calloc(REPLY_BUF_LENGTH, sizeof(char));
    if (buf == NULL) {
        return -1;
    }
    int ret = WpaCliCmd("STATUS", buf, REPLY_BUF_LENGTH);
    if (ret != 0) {
        free(buf);
        return -1;
    }
    /* Parsing the buf */
    /* Obtain the first substring and change buftest to buf. */
    char *savedPtr = NULL;
    char *key = strtok_r(buf, "=", &savedPtr);
    while (key != NULL) {
        char *value = strtok_r(NULL, "\n", &savedPtr);
        if (strcmp(key, "bssid") == 0) {
            MySafeCopy(pcmd->bssid, sizeof(pcmd->bssid), value);
        } else if (strcmp(key, "freq") == 0) {
            pcmd->freq = atoi(value);
        } else if (strcmp(key, "ssid") == 0) {
            MySafeCopy(pcmd->ssid, sizeof(pcmd->ssid), value);
        } else if (strcmp(key, "id") == 0) {
            pcmd->id = atoi(value);
        } else if (strcmp(key, "key_mgmt") == 0) {
            MySafeCopy(pcmd->key_mgmt, sizeof(pcmd->key_mgmt), value);
        } else if (strcmp(key, "address") == 0) {
            MySafeCopy(pcmd->address, sizeof(pcmd->address), value);
        }

        key = strtok_r(NULL, "=", &savedPtr);
    }
    free(buf);
    if (strcmp(pcmd->address, "") == 0) {
        return -1;
    }
    if (strcmp(pcmd->bssid, "") == 0) {
        LOGE("status success, but no wifi connect");
        return 1;
    }
    return 0;
}

static int WpaCliCmdAddNetworks(void)
{
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    int ret = WpaCliCmd("ADD_NETWORK", buf, sizeof(buf));
    if (ret != 0) {
        return -1;
    }
    return atoi(buf);
}

static int WpaCliCmdReconnect(void)
{
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    int ret = WpaCliCmd("RECONNECT", buf, sizeof(buf));
    if (ret != 0) {
        return -1;
    } else if (strncmp(buf, "OK", CMD_RETURN_OK_LENGTH) == 0) {
        LOGD("RECONNECT return ok");
        return 0;
    } else {
        LOGE("reconnect success, but result err, buf = %s", buf);
        return -1;
    }
}

static int WpaCliCmdReassociate(void)
{
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    int ret = WpaCliCmd("REASSOCIATE", buf, sizeof(buf));
    if (ret != 0) {
        return -1;
    } else if (strncmp(buf, "OK", CMD_RETURN_OK_LENGTH) == 0) {
        LOGD("REASSOCIATE return ok");
        return 0;
    } else {
        LOGE("REASSOCIATE success, but result err, buf = %s", buf);
        return -1;
    }
}

static int WpaCliCmdDisconnect(void)
{
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    int ret = WpaCliCmd("DISCONNECT", buf, sizeof(buf));
    if (ret != 0) {
        return -1;
    } else if (strncmp(buf, "OK", CMD_RETURN_OK_LENGTH) == 0) {
        LOGD("DISCONNECT return ok");
        return 0;
    } else {
        LOGE("DISCONNECT success, but result err, buf = %s", buf);
        return -1;
    }
}

static int WpaCliCmdSaveConfig(void)
{
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    int ret = WpaCliCmd("SAVE_CONFIG", buf, sizeof(buf));
    if (ret != 0) {
        return -1;
    } else if (strncmp(buf, "OK", CMD_RETURN_OK_LENGTH) == 0) {
        LOGD("SAVE_CONFIG return ok");
        return 0;
    } else {
        LOGE("save_config success, but result err,buf = %s", buf);
        return -1;
    }
}

static int WpaCliCmdSetNetwork(const struct WpaSetNetworkArgv *argv)
{
    int pos = -1;
    for (unsigned i = 0; i < sizeof(g_wpaSsidFields) / sizeof(g_wpaSsidFields[0]); ++i) {
        if (g_wpaSsidFields[i].field == argv->param) {
            pos = i;
            break;
        }
    }
    if (pos < 0) {
        LOGE("unsupported param: %{public}d", argv->param);
        return -1;
    }
    char cmdbuf[CMD_BUFFER_SIZE] = {0};
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    int res;
    if (g_wpaSsidFields[pos].flag == 0) {
        res = snprintf_s(cmdbuf,
            sizeof(cmdbuf),
            sizeof(cmdbuf) - 1,
            "%s %d %s \"%s\"",
            "SET_NETWORK",
            argv->id,
            g_wpaSsidFields[pos].fieldName,
            argv->value);
    } else {
        res = snprintf_s(cmdbuf,
            sizeof(cmdbuf),
            sizeof(cmdbuf) - 1,
            "%s %d %s %s",
            "SET_NETWORK",
            argv->id,
            g_wpaSsidFields[pos].fieldName,
            argv->value);
    }
    if (res < 0) {
        LOGE("Internal error, set request message failed!");
        return -1;
    }
    int ret = WpaCliCmd(cmdbuf, buf, sizeof(buf));
    if (ret != 0) {
        return -1;
    } else if (strncmp(buf, "OK", CMD_RETURN_OK_LENGTH) == 0) {
        LOGD("SET_NETWORK return ok");
        return 0;
    } else {
        LOGE("SET_NETWORK success, but result err, buf = %s", buf);
        return -1;
    }
}

static int WpaCliCmdEnableNetwork(int networkId)
{
    char cmdbuf[CMD_BUFFER_SMALL_SIZE] = {0};
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    int res = snprintf_s(cmdbuf, sizeof(cmdbuf), sizeof(cmdbuf) - 1, "%s %d", "ENABLE_NETWORK", networkId);
    if (res < 0) {
        LOGD("snprintf err");
        return -1;
    }
    int ret = WpaCliCmd(cmdbuf, buf, sizeof(buf));
    if (ret != 0) {
        return -1;
    } else if (strncmp(buf, "OK", CMD_RETURN_OK_LENGTH) == 0) {
        LOGD("ENABLE_NETWORK return ok");
        return 0;
    } else {
        LOGE("ENABLE_NETWORK success, but result err,buf = %s", buf);
        return -1;
    }
}

static int WpaCliCmdSelectNetwork(int networkId)
{
    char cmdbuf[CMD_BUFFER_SMALL_SIZE] = {0};
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    int res = snprintf_s(cmdbuf, sizeof(cmdbuf), sizeof(cmdbuf) - 1, "%s %d", "SELECT_NETWORK", networkId);
    if (res < 0) {
        LOGD("snprintf err");
        return -1;
    }
    int ret = WpaCliCmd(cmdbuf, buf, sizeof(buf));
    if (ret != 0) {
        return -1;
    } else if (strncmp(buf, "OK", CMD_RETURN_OK_LENGTH) == 0) {
        LOGD("SELECT_NETWORK return ok");
        return 0;
    } else {
        LOGE("select_network success, but result err,buf = %s", buf);
        return -1;
    }
}

static int WpaCliCmdDisableNetwork(int networkId)
{
    char cmdbuf[CMD_BUFFER_SMALL_SIZE] = {0};
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    int res = snprintf_s(cmdbuf, sizeof(cmdbuf), sizeof(cmdbuf) - 1, "%s %d", "DISABLE_NETWORK", networkId);
    if (res < 0) {
        LOGD("snprintf err");
        return -1;
    }
    int ret = WpaCliCmd(cmdbuf, buf, sizeof(buf));
    if (ret != 0) {
        return -1;
    } else if (strncmp(buf, "OK", CMD_RETURN_OK_LENGTH) == 0) {
        LOGD("DISABLE_NETWORK return ok");
        return 0;
    } else {
        LOGE("disable_network success, but result err,buf = %s", buf);
        return -1;
    }
}

static int WpaCliCmdRemoveNetwork(int networkId)
{
    char cmdbuf[CMD_BUFFER_SMALL_SIZE] = {0};
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    int res = snprintf_s(cmdbuf, sizeof(cmdbuf), sizeof(cmdbuf) - 1, "%s %d", "REMOVE_NETWORK", networkId);
    if (res < 0) {
        LOGD("snprintf err");
        return -1;
    }
    int ret = WpaCliCmd(cmdbuf, buf, sizeof(buf));
    if (ret != 0) {
        return -1;
    } else if (strncmp(buf, "OK", CMD_RETURN_OK_LENGTH) == 0) {
        LOGD("REMOVE_NETWORK return ok");
        return 0;
    } else {
        LOGE("remove_network success, but result err, buf = %s", buf);
        return -1;
    }
}

static int WpaCliCmdGetNetwork(const struct WpaGetNetworkArgv *argv, char *pcmd, unsigned size)
{
    char cmdbuf[CMD_BUFFER_SIZE] = {0};
    int res = snprintf_s(cmdbuf, sizeof(cmdbuf), sizeof(cmdbuf) - 1, "%s %d %s", "GET_NETWORK", argv->id, argv->parame);
    if (res < 0) {
        LOGD("snprintf err");
        return -1;
    }
    char *buf = (char *)calloc(REPLY_BUF_LENGTH, sizeof(char));
    if (buf == NULL) {
        return -1;
    }
    int ret = WpaCliCmd(cmdbuf, buf, REPLY_BUF_LENGTH);
    if (ret != 0) {
        free(buf);
        return -1;
    }
    if (strncpy_s(pcmd, size, buf, strlen(buf)) != EOK) {
        LOGE("copy set get_network result failed!");
        free(buf);
        return -1;
    }
    LOGD("get_network return ok, buf = %s", buf);
    free(buf);
    return 0;
}

static int WpaCliCmdWpsPbc(const struct WpaWpsPbcArgv *wpspbc)
{
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmdbuf[CMD_BUFFER_SIZE] = {0};
    int pos = 0;
    int res = snprintf_s(cmdbuf, sizeof(cmdbuf), sizeof(cmdbuf) - 1, "%s", "WPS_PBC");
    if (res < 0) {
        LOGD("snprintf err");
        return -1;
    }
    pos += res;
    if (wpspbc != NULL) {
        if (wpspbc->anyflag == 1) {
            res = snprintf_s(cmdbuf + pos, sizeof(cmdbuf) - pos, sizeof(cmdbuf) - pos - 1, " %s", "any");
            if (res < 0) {
                LOGE("snprintf err");
                return -1;
            }
            pos += res;
        } else if (strlen(wpspbc->bssid) > 0) {
            res = snprintf_s(cmdbuf + pos, sizeof(cmdbuf) - pos, sizeof(cmdbuf) - pos - 1, " %s", wpspbc->bssid);
            if (res < 0) {
                LOGE("snprintf err");
                return -1;
            }
            pos += res;
        }
        if (wpspbc->multi_ap > 0) { /* The value of ap needs to be determined. The value is greater than 0. */
            res = snprintf_s(
                cmdbuf + pos, sizeof(cmdbuf) - pos, sizeof(cmdbuf) - pos - 1, " multi_ap=%d", wpspbc->multi_ap);
            if (res < 0) {
                LOGE("snprintf err");
                return -1;
            }
        }
    }
    int ret = WpaCliCmd(cmdbuf, buf, sizeof(buf));
    if (ret != 0) {
        LOGD("wps_pbc return failed!");
        return -1;
    } else if (strncmp(buf, "OK", CMD_RETURN_OK_LENGTH) == 0) {
        return 0;
    } else {
        if (strncmp(buf, "FAIL-PBC-OVERLAP", strlen("FAIL-PBC-OVERLAP")) == 0) {
            LOGE("wps_pbc success, but result err: buf =%s", buf);
            return FAIL_PBC_OVERLAP_RETUEN; /* Add a new enumerated value. */
        }
        LOGE("wps_pbc success, but result err: buf =%s", buf);
        return -1;
    }
}

static int WpaCliCmdWpsPin(const struct WpaWpsPinArgv *wpspin, int *pincode)
{
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmdbuf[CMD_BUFFER_SIZE] = {0};
    int pos = 0;
    int res = snprintf_s(cmdbuf, sizeof(cmdbuf), sizeof(cmdbuf) - 1, "%s", "WPS_PIN");
    if (res < 0) {
        LOGE("snprintf err");
        return -1;
    }
    pos += res;
    if (strlen(wpspin->bssid) > 0) {
        res = snprintf_s(cmdbuf + pos, sizeof(cmdbuf) - pos, sizeof(cmdbuf) - pos - 1, " %s", wpspin->bssid);
    } else {
        res = snprintf_s(cmdbuf + pos, sizeof(cmdbuf) - pos, sizeof(cmdbuf) - pos - 1, " any");
    }
    if (res < 0) {
        LOGE("snprintf err");
        return -1;
    }
    int ret = WpaCliCmd(cmdbuf, buf, sizeof(buf));
    if (ret != 0) {
        return -1;
    } else {
        *pincode = atoi(buf);
        return 0;
    }
}

static int WpaCliCmdWpsCancel(void)
{
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    int ret = WpaCliCmd("WPS_CANCEL", buf, sizeof(buf));
    if (ret != 0) {
        return -1;
    } else if (strncmp(buf, "OK", CMD_RETURN_OK_LENGTH) == 0) {
        LOGD("wps_cancel return ok");
        return 0;
    } else {
        LOGE("wps_cancel success, but result err: buf =%s", buf);
        return -1;
    }
}

static int WpaCliCmdPowerSave(BOOL enable)
{
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    int ret = 0;
    if (enable) {
        ret = WpaCliCmd("SET PS 1", buf, sizeof(buf));
    } else {
        ret = WpaCliCmd("SET PS 0", buf, sizeof(buf));
    }

    if (ret != 0) {
        LOGD("powersave cmd send failed!");
        return ret;
    } else {
        LOGD("powersave cmd send success!");
        if (strncmp(buf, "OK", CMD_RETURN_OK_LENGTH) == 0) {
            LOGD("powersave return ok.");
            return 0;
        } else {
            LOGE("powersave success, but result err: buf =%s", buf);
            return -1;
        }
    }
}

static int WpaCliCmdSetCountryCode(const char *countryCode)
{
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmdbuf[CMD_BUFFER_SMALL_SIZE] = {0};
    int res = snprintf_s(cmdbuf, sizeof(cmdbuf), sizeof(cmdbuf) - 1, "SET country %s", countryCode);
    if (res < 0) {
        LOGE("snprintf err");
        return -1;
    }
    int ret = WpaCliCmd(cmdbuf, buf, sizeof(buf));
    if (ret != 0) {
        return -1;
    } else if (strncmp(buf, "OK", CMD_RETURN_OK_LENGTH) == 0) {
        LOGD("set country code return ok");
        return 0;
    } else {
        LOGE("set country code success, but result err: buf =%s", buf);
        return -1;
    }
}

static int WpaCliCmdGetCountryCode(char *countryCode, int codeSize)
{
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    int ret = WpaCliCmd("GET country", buf, sizeof(buf));
    if (ret != 0) {
        return -1;
    } else if (strncmp(buf, "FAIL", strlen("FAIL")) == 0) {
        LOGD("get countrycode failed");
        return -1;
    } else {
        if (strncpy_s(countryCode, codeSize, buf, strlen(buf)) != EOK) {
            LOGE("copy set country code failed!");
            return -1;
        }
        LOGD("get countrycode ok, countryCode = %{public}s", countryCode);
        return 0;
    }
}

static int WpaCliCmdSetAutoConnect(int enable)
{
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmdbuf[CMD_BUFFER_SMALL_SIZE] = {0};
    int res = snprintf_s(cmdbuf, sizeof(cmdbuf), sizeof(cmdbuf) - 1, "STA_AUTOCONNECT %d", enable);
    if (res < 0) {
        LOGE("snprintf err");
        return -1;
    }
    int ret = WpaCliCmd(cmdbuf, buf, sizeof(buf));
    if (ret != 0) {
        return -1;
    } else if (strncmp(buf, "OK", CMD_RETURN_OK_LENGTH) == 0) {
        LOGD("SetAutoConnect return ok");
        return 0;
    } else {
        LOGE("SetAutoConnect success, but result err: buf =%s", buf);
        return -1;
    }
}

static int WpaCliCmdReconfigure(void)
{
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    int ret = WpaCliCmd("RECONFIGURE", buf, sizeof(buf));
    if (ret != 0) {
        return -1;
    } else if (strncmp(buf, "OK", CMD_RETURN_OK_LENGTH) == 0) {
        LOGD("WpaCliCmdReconfigure return ok");
        return 0;
    } else {
        LOGE("WpaCliCmdReconfigure success, but result err: buf =%s", buf);
        return -1;
    }
}

static int WpaCliCmdWpaBlockListClear(void)
{
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmdbuf[CMD_BUFFER_SMALL_SIZE] = {0};
    int res = snprintf_s(cmdbuf, sizeof(cmdbuf), sizeof(cmdbuf) - 1, "BL%cCKLIST clear", 'A');
    if (res < 0) {
        LOGE("snprintf err");
        return -1;
    }
    int ret = WpaCliCmd(cmdbuf, buf, sizeof(buf));
    if (ret != 0) {
        return -1;
    } else if (strncmp(buf, "OK", CMD_RETURN_OK_LENGTH) == 0) {
        LOGD("WpaCliCmdWpaBlockListClear return ok");
        return 0;
    } else {
        LOGE("WpaCliCmdWpaBlockListClear success, but result err: buf =%s", buf);
        return -1;
    }
}

static void ListNetworkProcess(NetworkList *pcmd, char *tmpBuf, int bufLeng)
{
    int start = 0; /* start pos */
    int end = 0;   /* end pos */
    int i = 0;
    while (end < bufLeng) {
        if (tmpBuf[end] != '\t') {
            ++end;
            continue;
        }
        tmpBuf[end] = '\0';
        if (i == SCAN_RESULT_NONE) {
            pcmd->id = atoi(tmpBuf);
        } else if (i == SCAN_RESULT_ONE) {
            if (strcpy_s(pcmd->ssid, sizeof(pcmd->ssid), tmpBuf + start) != EOK) {
                break;
            }
        } else if (i == SCAN_RESULT_TWO) {
            if (strcpy_s(pcmd->bssid, sizeof(pcmd->bssid), tmpBuf + start) != EOK) {
                break;
            }
            start = end + 1;
            if (strcpy_s(pcmd->flags, sizeof(pcmd->flags), tmpBuf + start) != EOK) {
                break;
            }
            break;
        }
        ++i;
        end++;
        start = end;
    }
    return;
}

/* cmd: list_networks */
static int WpaCliCmdListNetworks(NetworkList *pcmd, int *size)
{
    char *buf = (char *)calloc(REPLY_BUF_LENGTH, sizeof(char));
    if (buf == NULL) {
        return -1;
    }
    int ret = WpaCliCmd("LIST_NETWORKS", buf, REPLY_BUF_LENGTH);
    if (ret != 0) {
        free(buf);
        return -1;
    }
    char *savedPtr = NULL;
    char *token = strtok_r(buf, "\n", &savedPtr);
    if (token == NULL) {
        free(buf);
        return -1;
    }
    token = strtok_r(NULL, "\n", &savedPtr);
    int j = 0;

    while (token != NULL) {
        if (j >= CMD_RESULT_MAX_NUM || j >= *size) {
            *size = j;
            LOGE("list_networks full!");
            free(buf);
            return 0;
        }
        int length = strlen(token);
        if (length <= 0) {
            break;
        }
        ListNetworkProcess(pcmd + j, token, length);
        token = strtok_r(NULL, "\n", &savedPtr);
        j++;
    }
    *size = j;
    if (*size <= 0) {
        LOGE("list_networks empty!");
    }
    free(buf);
    return 0;
}

static int ConcatScanSetting(const ScanSettings *settings, char *buff, int len)
{
    if (settings == NULL) {
        return 0;
    }
    int pos = 0;
    int res;
    int i;
    for (i = 0; i < settings->freqSize; ++i) {
        if (i == 0) {
            res = snprintf_s(buff + pos, len - pos, len - pos - 1, "%s", " freq=");
            if (res < 0) {
                LOGE("snprintf error");
                return -1;
            }
            pos += res;
        }
        if (i != (settings->freqSize - 1)) {
            res = snprintf_s(buff + pos, len - pos, len - pos - 1, "%d,", settings->freqs[i]);
        } else {
            res = snprintf_s(buff + pos, len - pos, len - pos - 1, "%d;", settings->freqs[i]);
        }
        if (res < 0) {
            LOGE("snprintf error");
            return -1;
        }
        pos += res;
    }
    for (i = 0; i < settings->hiddenSsidSize; ++i) {
        res = snprintf_s(buff + pos, len - pos, len - pos - 1, " ssid ");
        if (res < 0) {
            LOGE("snprintf error");
            return -1;
        }
        pos += res;
        char *p = settings->hiddenSsid[i];
        while (*p) {
            res = snprintf_s(buff + pos, len - pos, len - pos - 1, "%02x", *p);
            if (res < 0) {
                LOGE("snprintf error");
                return -1;
            }
            pos += res;
            p++;
        }
    }
    return 0;
}

static int WpaCliCmdScan(const ScanSettings *settings)
{
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmdbuf[CMD_BUFFER_SIZE] = {0};
    int pos = 0;
    int res = snprintf_s(cmdbuf, sizeof(cmdbuf), sizeof(cmdbuf) - 1, "%s", "SCAN");
    if (res < 0) {
        LOGE("snprintf error");
        return -1;
    }
    pos += res;
    if (settings != NULL) {
        res = ConcatScanSetting(settings, cmdbuf + pos, sizeof(cmdbuf) - pos);
        if (res < 0) {
            LOGE("snprintf scan settings error");
            return -1;
        }
    }
    int ret = WpaCliCmd(cmdbuf, buf, sizeof(buf));
    if (ret != 0) {
        return -1;
    } else if (strncmp(buf, "OK", CMD_RETURN_OK_LENGTH) == 0) {
        LOGD("scan return ok");
        return 0;
    } else {
        LOGE("scan success, but result err: buf =[%{public}s]", buf);
        if (strncmp(buf, "FAIL-BUSY", strlen("FAIL-BUSY")) == 0) {
            return FAIL_BUSY;
        }
        return -1;
    }
}

static int DelScanResultLine(ScanResult *pcmd, char *srcBuf, int length)
{
    int i = 0;
    int start = 0;
    int end = 0;
    int fail = 0;
    while (end < length) {
        if (srcBuf[end] != '\t') {
            ++end;
            continue;
        }
        srcBuf[end] = '\0';
        if (i == 0) {
            if (strcpy_s(pcmd->bssid, sizeof(pcmd->bssid), srcBuf + start) != EOK) {
                fail = 1;
                break;
            }
        } else if (i == 1) {
            pcmd->freq = atoi(srcBuf + start);
        } else if (i == SCAN_RESULT_TWO) {
            pcmd->siglv = atoi(srcBuf + start);
        } else if (i == SCAN_RESULT_THREE) {
            if (strcpy_s(pcmd->flags, sizeof(pcmd->flags), srcBuf + start) != EOK) {
                fail = 1;
                break;
            }
            start = end + 1;
            if (strcpy_s(pcmd->ssid, sizeof(pcmd->ssid), srcBuf + start) != EOK) {
                fail = 1;
                break;
            }
            start = length;
            break;
        }
        ++i;
        ++end;
        start = end;
    }
    if (fail == 0 && start < length) {
        if (strcpy_s(pcmd->flags, sizeof(pcmd->flags), srcBuf + start) != EOK) {
            fail = 1;
        }
    }
    return fail;
}

static int WpaCliCmdScanResult(ScanResult *pcmd, int *size)
{
    char *buf = (char *)calloc(REPLY_BUF_LENGTH, sizeof(char));
    if (buf == NULL) {
        return -1;
    }
    int ret = WpaCliCmd("SCAN_RESULTS", buf, REPLY_BUF_LENGTH);
    if (ret != 0) {
        free(buf);
        return -1;
    }
    /* skip the first line. */
    char *savedPtr = NULL;
    char *token = strtok_r(buf, "\n", &savedPtr);
    if (token == NULL) {
        free(buf);
        return -1;
    }
    token = strtok_r(NULL, "\n", &savedPtr);
    int j = 0;
    while (token != NULL) {
        if (j >= CMD_RESULT_MAX_NUM || j >= *size) {
            *size = j;
            LOGE("scan_result full!");
            free(buf);
            return 0;
        }
        int length = strlen(token);
        if (length <= 0) {
            break;
        }
        if (DelScanResultLine(&pcmd[j], token, length)) {
            LOGE("parse scan result line failed!");
            break;
        }
        token = strtok_r(NULL, "\n", &savedPtr);
        j++;
    }
    *size = j;
    free(buf);
    return 0;
}

/* Open Device Function */
WifiHalDevice *GetWifiHalDev(void)
{
    if (g_wpaHalDev != NULL) {
        return g_wpaHalDev;
    }
    g_wpaHalDev = (WifiHalDevice *)calloc(1, sizeof(WifiHalDevice));
    if (g_wpaHalDev == NULL) {
        LOGE("NULL device on open");
        return NULL;
    }
    // wpa_cli Interface registration
    g_wpaHalDev->WifiWpaCliConnectWpa = WifiWpaCliConnectWpa;
    g_wpaHalDev->WifiWpaCliWpaCtrlClose = WifiWpaCliWpaCtrlClose;
    g_wpaHalDev->WpaCliCmdStatus = WpaCliCmdStatus;
    g_wpaHalDev->WpaCliCmdAddNetworks = WpaCliCmdAddNetworks;
    g_wpaHalDev->WpaCliCmdReconnect = WpaCliCmdReconnect;
    g_wpaHalDev->WpaCliCmdReassociate = WpaCliCmdReassociate;
    g_wpaHalDev->WpaCliCmdDisconnect = WpaCliCmdDisconnect;
    g_wpaHalDev->WpaCliCmdSaveConfig = WpaCliCmdSaveConfig;
    g_wpaHalDev->WpaCliCmdSetNetwork = WpaCliCmdSetNetwork;
    g_wpaHalDev->WpaCliCmdEnableNetwork = WpaCliCmdEnableNetwork;
    g_wpaHalDev->WpaCliCmdSelectNetwork = WpaCliCmdSelectNetwork;
    g_wpaHalDev->WpaCliCmdDisableNetwork = WpaCliCmdDisableNetwork;
    g_wpaHalDev->WpaCliCmdRemoveNetwork = WpaCliCmdRemoveNetwork;
    g_wpaHalDev->WpaCliCmdGetNetwork = WpaCliCmdGetNetwork;
    g_wpaHalDev->WpaCliCmdWpsPbc = WpaCliCmdWpsPbc;
    g_wpaHalDev->WpaCliCmdWpsPin = WpaCliCmdWpsPin;
    g_wpaHalDev->WpaCliCmdWpsCancel = WpaCliCmdWpsCancel;
    g_wpaHalDev->WpaCliCmdPowerSave = WpaCliCmdPowerSave;
    g_wpaHalDev->WpaCliCmdSetCountryCode = WpaCliCmdSetCountryCode;
    g_wpaHalDev->WpaCliCmdGetCountryCode = WpaCliCmdGetCountryCode;
    g_wpaHalDev->WpaCliCmdSetAutoConnect = WpaCliCmdSetAutoConnect;
    g_wpaHalDev->WpaCliCmdReconfigure = WpaCliCmdReconfigure;
    g_wpaHalDev->WpaCliCmdWpaBlockListClear = WpaCliCmdWpaBlockListClear;
    g_wpaHalDev->WpaCliCmdListNetworks = WpaCliCmdListNetworks;
    g_wpaHalDev->WpaCliCmdScan = WpaCliCmdScan;
    g_wpaHalDev->WpaCliCmdScanResult = WpaCliCmdScanResult;

    return g_wpaHalDev;
}

void ReleaseWpaHalDev(void)
{
    if (g_wpaHalDev != NULL) {
        WifiWpaCliWpaCtrlClose();
        free(g_wpaHalDev);
        g_wpaHalDev = NULL;
    }
}
