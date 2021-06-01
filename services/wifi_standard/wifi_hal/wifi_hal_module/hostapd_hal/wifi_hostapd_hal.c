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

#include "wifi_hostapd_hal.h"
#include <malloc.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "securec.h"
#include "common/wpa_ctrl.h"
#include "wifi_hal_callback.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "WifiHostapdHal"

#define CONFIG_PATH_DIR "/data/misc/wifi/hostapd"

#define CONFIG_CTRL_IFACE_NAME "wlan0"
/**
 * Blocklist configuration file name. This parameter is used by hostapd in an
 * earlier version.
 */
#define CONFIG_DENY_MAC_FILE_NAME "deny_mac.conf"
#define SLEEP_TIME_100_MS (100 * 1000)

WifiHostapdHalDevice *g_hostapdHalDev = NULL; /* Global Variable */

/*
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
    } else if (ret == 0) {
        return 0;
    } else {
        return 1;
    }
}

static void DelCallbackMessage(const char *msg)
{
    if (msg == NULL) {
        return;
    }
    if (strncmp(msg, AP_STA_CONNECTED, strlen(AP_STA_CONNECTED)) == 0 ||
        strncmp(msg, AP_STA_DISCONNECTED, strlen(AP_STA_DISCONNECTED)) == 0) {
        /* STA Join/Leave Event */
        WifiHalCbSTAJoin(msg);
    } else if (strncmp(msg, AP_EVENT_ENABLED, strlen(AP_EVENT_ENABLED)) == 0 ||
               strncmp(msg, AP_EVENT_DISABLED, strlen(AP_EVENT_DISABLED)) == 0 ||
               strncmp(msg, WPA_EVENT_TERMINATING, strlen(WPA_EVENT_TERMINATING)) == 0) {
        /* AP Enable/Disable Event */
        if (strncmp(msg, AP_EVENT_DISABLED, strlen(AP_EVENT_DISABLED)) == 0 && g_hostapdHalDev->execDisable == 1) {
            g_hostapdHalDev->execDisable = 0;
            return;
        }
        WifiHalCbAPState(msg);
        if (strncmp(msg, WPA_EVENT_TERMINATING, strlen(WPA_EVENT_TERMINATING)) == 0) {
            g_hostapdHalDev->threadRunFlag = 0;
        }
    }
}

static void *HostapdReceiveCallback(void *arg)
{
    struct wpa_ctrl *ctrl = arg;
    char *buf = (char *)calloc(BUFSIZE_RECV, sizeof(char));
    if (buf == NULL) {
        LOGE("In hostapd deal receive message thread, failed to calloc buff!");
        return NULL;
    }
    while (g_hostapdHalDev->threadRunFlag) {
        int ret = MyWpaCtrlPending(ctrl);
        if (ret < 0) {
            LOGE("hostapd thread get event message failed!");
            break;
        } else if (ret == 0) {
            continue;
        }
        if (memset_s(buf, BUFSIZE_RECV, 0, BUFSIZE_RECV) != EOK) {
            LOGE("thread clear buffer cache failed!");
            break;
        }
        size_t len = BUFSIZE_RECV - 1;
        ret = wpa_ctrl_recv(ctrl, buf, &len);
        if (ret < 0) {
            LOGE("hostapd thread read event message failed!");
            break;
        }
        if (len <= 0) {
            LOGE("thread read event message leng err!");
            continue;
        }
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
        DelCallbackMessage(p);
    }
    free(buf);
    LOGI("=====================hostapd thread exist=======================");
    return NULL;
}

static struct wpa_ctrl *HostapdCliOpenConnection(const char *ifname)
{
    struct wpa_ctrl *ctrl = NULL;
    if (ifname == NULL) {
        return NULL;
    }
    int count = 30;
    while (count) {
        ctrl = wpa_ctrl_open(ifname);
        if (ctrl == NULL) {
            usleep(SLEEP_TIME_100_MS);
            count--;
        } else {
            break;
        }
    }
    return ctrl;
}

static int HostapdCliConnect(void)
{
    int retval = -1;
    do {
        g_hostapdHalDev->ctrlConn = HostapdCliOpenConnection(CONFIG_CTRL_IFACE_NAME);
        g_hostapdHalDev->ctrlRecv = HostapdCliOpenConnection(CONFIG_CTRL_IFACE_NAME);
        if (g_hostapdHalDev->ctrlConn == NULL || g_hostapdHalDev->ctrlRecv == NULL) {
            LOGE("open hostapd control interface failed!");
            break;
        }

        if (wpa_ctrl_attach(g_hostapdHalDev->ctrlRecv) != 0) {
            LOGE("hostapd attach failed!");
            break;
        }
        g_hostapdHalDev->threadRunFlag = 1;
        if (pthread_create(&g_hostapdHalDev->tid, NULL, HostapdReceiveCallback, g_hostapdHalDev->ctrlRecv) != 0) {
            wpa_ctrl_detach(g_hostapdHalDev->ctrlRecv);
            LOGE("hostapd Create monitor thread failed!");
            break;
        }
        retval = 0;
    } while (0);

    if (retval != 0) {
        if (g_hostapdHalDev->ctrlConn != NULL) {
            wpa_ctrl_close(g_hostapdHalDev->ctrlConn);
            g_hostapdHalDev->ctrlConn = NULL;
        }
        if (g_hostapdHalDev->ctrlRecv != NULL) {
            wpa_ctrl_close(g_hostapdHalDev->ctrlRecv);
            g_hostapdHalDev->ctrlRecv = NULL;
        }
    }
    return retval;
}

static int HostapdCliClose(void)
{
    if (g_hostapdHalDev->ctrlConn != NULL) {
        g_hostapdHalDev->threadRunFlag = 0;
        pthread_join(g_hostapdHalDev->tid, NULL);
        g_hostapdHalDev->tid = 0;
        wpa_ctrl_close(g_hostapdHalDev->ctrlRecv);
        g_hostapdHalDev->ctrlRecv = NULL;
        wpa_ctrl_close(g_hostapdHalDev->ctrlConn);
        g_hostapdHalDev->ctrlConn = NULL;
    }
    return 0;
}

static int WpaCtrlCommand(struct wpa_ctrl *ctrl, const char *cmd, char *buf, size_t bufSize)
{
    if (ctrl == NULL || bufSize <= 0) {
        LOGE("Not connected to hostapd - command dropped.");
        return -1;
    }
    size_t len = bufSize - 1;
    int ret = wpa_ctrl_request(ctrl, cmd, strlen(cmd), buf, &len, NULL);
    if (ret == REQUEST_FAILED) {
        LOGE("Command timed out.");
        return ret;
    } else if (ret < 0) {
        LOGE("Command failed.");
        return -1;
    }

    buf[len] = '\0';
    if (memcmp(buf, "FAIL", FAIL_LENTH) == 0) {
        return -1;
    }
    return 0;
}

/* Enable Hotspot */
static int EnableAp(void)
{
    char buf[BUFSIZE_REQUEST_SMALL] = {0};
    int retval = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, "ENABLE", buf, sizeof(buf));
    if (strncmp(buf, "OK", OK_LENTH) != 0) {
        retval = -1;
    }
    return retval;
}

static int SetApName(const char *name)
{
    int retval = -1;
    if (name == NULL) {
        return retval;
    }
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "SET ssid %s", name) < 0) {
        return -1;
    }
    retval = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
    if (strncmp(buf, "OK", OK_LENTH) != 0) {
        LOGE("SetApName Failed");
        retval = -1;
    }

    return retval;
}

/* Setting the Security Authentication Mode */
static int SetApRsnPairwise(const char *type)
{
    if (type == NULL) {
        return -1;
    }

    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "SET rsn_pairwise %s", type) < 0) {
        return -1;
    }
    int retval = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
    if (strncmp(buf, "OK", OK_LENTH) != 0) {
        LOGE("SetApRsnPairwise Failed");
        retval = -1;
    }

    return retval;
}

static int SetApWpaPairwise(const char *type)
{
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "SET wpa_pairwise %s", type) < 0) {
        return -1;
    }
    int retval = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
    if (strncmp(buf, "OK", OK_LENTH) != 0) {
        LOGE("SetApWpaPairwise Failed");
        retval = -1;
    }

    return retval;
}

static int SetApWpaKeyMgmt(const char *type)
{
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "SET wpa_key_mgmt %s", type) < 0) {
        return -1;
    }
    int retval = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
    if (strncmp(buf, "OK", OK_LENTH) != 0) {
        LOGE("SetApWpaKeyMgmt Failed");
        retval = -1;
    }

    return retval;
}

static int SetApWpaValue(int securityType)
{
    int retval = -1;
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    switch (securityType) {
        case NONE:
            /*
             * The authentication mode is NONE and the
             * authentication type is Open.
             */
            retval = sprintf_s(cmd, sizeof(cmd), "SET wpa 0");
            break;
        case WPA_PSK:
            retval = sprintf_s(cmd, sizeof(cmd), "SET wpa 1"); /* The authentication mode is WPA-PSK. */
            break;
        case WPA2_PSK:
            retval = sprintf_s(cmd, sizeof(cmd), "SET wpa 2"); /* The authentication mode is WPA2-PSK. */
            break;
        default:
            LOGE("Unknown encryption type!");
            return retval;
    }
    if (retval < 0) {
        return -1;
    }

    retval = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
    if (strncmp(buf, "OK", OK_LENTH) != 0) {
        LOGE("SetApWpaValue Failed");
        retval = -1;
    }
    if (retval == 0 && securityType != NONE) {
        /*
         * If the value of wpa is switched between 0, 1, and 2, the wpa_key_mgmt,
         * wpa_pairwise, and rsn_pairwise attributes must be set. Otherwise, the
         * enable or STA cannot be connected.
         */
        retval = SetApWpaKeyMgmt("WPA-PSK");
    }
    if (retval == 0 && securityType == WPA_PSK) {
        retval = SetApWpaPairwise("CCMP");
    }
    if (retval == 0 && securityType == WPA2_PSK) {
        retval = SetApRsnPairwise("CCMP");
    }
    return retval;
}

/* Setting Password */
static int SetApPasswd(const char *pass)
{
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "SET wpa_passphrase %s", pass) < 0) {
        return -1;
    }
    int retval = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
    if (strncmp(buf, "OK", OK_LENTH) != 0) {
        LOGE("SetApPasswd Failed cmd");
        retval = -1;
    }

    return retval;
}

/* Setting Channel */
static int SetApChannel(int channel)
{
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "SET channel %d", channel) < 0) {
        return -1;
    }
    int retval = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
    if (strncmp(buf, "OK", OK_LENTH) != 0) {
        LOGE("SetApChannel Failed");
        retval = -1;
    }

    return retval;
}

/* Setting Band */
static int SetApBand(int band)
{
    int retval = -1;
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};
    const char *hwMode = NULL;

    switch (band) {
        case -1:
            LOGE("Dual-mode frequency band!");
            return retval;
        case AP_NONE_BAND:
            hwMode = "any"; /* Unknown frequency band */
            break;
        case AP_2GHZ_BAND:
            hwMode = "g"; /* BAND_2_4_GHZ */
            break;
        case AP_5GHZ_BAND:
            hwMode = "a"; /* BAND_5_GHZ */
            break;
        default:
            LOGE("Invalid band!");
            return retval;
    }

    if (sprintf_s(cmd, sizeof(cmd), "SET hw_mode %s", hwMode) < 0) {
        return -1;
    }
    retval = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
    if (strncmp(buf, "OK", OK_LENTH) != 0) {
        LOGE("SetApBand Failed");
        retval = -1;
    }
    return retval;
}

/* Setting Max Connect Num */
static int SetApMaxConn(int maxConn)
{
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "SET max_num_sta %d", maxConn) < 0) {
        return -1;
    }
    int retval = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
    if (strncmp(buf, "OK", OK_LENTH) != 0) {
        LOGE("SetApMaxConn Failed");
        retval = -1;
    }

    return retval;
}

static int SetApInfo(HostsapdConfig *info)
{
    int retval = -1;
    if (info->securityType != NONE) {
        int passwdLen = strlen(info->preSharedKey);
        if (passwdLen < PASSWD_MIN_LEN || passwdLen != info->preSharedKey_len) {
            LOGE("password is invalid!");
            return retval;
        }
        if ((retval = SetApPasswd((char *)info->preSharedKey)) != 0) {
            LOGE("SetApPasswd failed. retval %{public}d", retval);
            return retval;
        }
    }
    if ((retval = SetApName((char *)info->ssid)) != 0) {
        LOGE("SetApName failed. retval %{public}d", retval);
        return retval;
    }
    if ((retval = SetApWpaValue(info->securityType)) != 0) {
        LOGE("SetApWpaValue failed. retval %{public}d", retval);
        return retval;
    }
    if ((retval = SetApBand(info->band)) != 0) {
        LOGE("SetApBand failed. retval %{public}d", retval);
        return retval;
    }
    if ((retval = SetApChannel(info->channel)) != 0) {
        LOGE("SetApChannel failed. retval %{public}d", retval);
        return retval;
    }
    if ((retval = SetApMaxConn(info->maxConn)) != 0) {
        LOGE("SetApMaxConn failed. retval %{public}d", retval);
        return retval;
    }
    return 0;
}

static int DisableAp(void)
{
    char buf[BUFSIZE_REQUEST_SMALL] = {0};
    g_hostapdHalDev->execDisable = 1;
    int retval = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, "DISABLE", buf, sizeof(buf));
    if (strncmp(buf, "OK", OK_LENTH) != 0) {
        LOGE("DisableAp Failed");
        retval = -1;
    }

    return retval;
}

static int ModBlockList(const char *mac)
{
    char buf[BUFSIZE_REQUEST_SMALL] = {0};
    char cmd[BUFSIZE_CMD] = {0};
    char file[FILE_NAME_SIZE] = {0};
    if (snprintf_s(file, sizeof(file), sizeof(file) - 1, "%s/%s", CONFIG_PATH_DIR, CONFIG_DENY_MAC_FILE_NAME) < 0) {
        return -1;
    }
    FILE *fp = fopen(file, "w");
    if (fp == NULL) {
        return -1;
    }
    if (fprintf(fp, "%s\n", mac) < 0) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    if (sprintf_s(cmd, sizeof(cmd), "SET deny_mac_file %s/%s", CONFIG_PATH_DIR, CONFIG_DENY_MAC_FILE_NAME) < 0) {
        return -1;
    }
    int ret = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
    if (strncmp(buf, "OK", OK_LENTH) != 0) {
        LOGE("ModBlockList Failed");
        ret = -1;
    }
    return ret;
}

static int AddBlocklist(const char *mac)
{
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "DENY_ACL ADD_MAC %s", mac) < 0) {
        return -1;
    }
    int retval = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
    if (strncmp(buf, "OK", OK_LENTH) != 0) {
        LOGE("AddBlocklist Failed");
        retval = -1;
    }
    if (strncasecmp(buf, "UNKNOWN COMMAND", UNKNOWN_COMMAND_LENTH) == 0) {
        /**
         * The hostapd of an earlier version does not support the DENY_ACL command
         * and uses the configuration file.
         */
        retval = ModBlockList(mac);
    }
    return retval;
}

static int DelBlocklist(const char *mac)
{
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "DENY_ACL DEL_MAC %s", mac) < 0) {
        return -1;
    }
    int retval = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
    if (strncmp(buf, "OK", OK_LENTH) != 0) {
        LOGE("DelBlocklist Failed");
        retval = -1;
    }
    if (strncasecmp(buf, "UNKNOWN COMMAND", UNKNOWN_COMMAND_LENTH) == 0) {
        /*
         * The hostapd of an earlier version does not support the DENY_ACL command
         * and uses the configuration file.
         */
        if (sprintf_s(cmd, sizeof(cmd), "-%s", mac) < 0) {
            return -1;
        }
        retval = ModBlockList(cmd);
    }
    return retval;
}

static int GetApStatus(StatusInfo *info)
{
    char *buf = (char *)calloc(BUFSIZE_REQUEST, sizeof(char));
    if (buf == NULL) {
        return -1;
    }

    int retval = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, "STATUS", buf, BUFSIZE_REQUEST);
    if (retval != 0) {
        LOGE("Status WpaCtrlCommand failed");
        free(buf);
        return -1;
    }

    char *p = strstr(buf, "state");
    if (p == NULL) {
        LOGD("Status not find state result!");
        free(buf);
        return 0;
    }
    p += strlen("state=");  // skip state=
    int pos = 0;
    while (*p != '\0' && *p != '\n') {
        info->state[pos++] = *p;
        ++p;
    }
    info->state[pos] = 0;
    free(buf);
    return retval;
}

static int HostapdCliCmdListSta(struct wpa_ctrl *ctrl, char *buf, const int *size)
{
    char cmd[BUFSIZE_CMD] = {0};
    char *reqBuf = (char *)calloc(BUFSIZE_REQUEST, sizeof(char));
    if (reqBuf == NULL) {
        return -1;
    }
    if (WpaCtrlCommand(ctrl, "STA-FIRST", reqBuf, BUFSIZE_REQUEST)) {
        LOGE("HostapdCliCmdListSta Failed");
        free(reqBuf);
        return -1;
    }
    do {
        char *pos = reqBuf;
        while (*pos != '\0' && *pos != '\n') { /* return station info, first line is mac address */
            pos++;
        }
        *pos = '\0';
        if (strcmp(reqBuf, "") != 0) {
            int bufLen = strlen(buf);
            int staLen = strlen(reqBuf);
            if (bufLen + staLen + 1 >= (*size)) {
                free(reqBuf);
                return 0;
            }
            buf[bufLen++] = ',';
            for (int i = 0; i < staLen; ++i) {
                buf[bufLen + i] = reqBuf[i];
            }
            buf[bufLen] = '\0';
        }
        if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "STA-NEXT %s", reqBuf) < 0) {
            break;
        }
    } while (WpaCtrlCommand(ctrl, cmd, reqBuf, BUFSIZE_REQUEST) == 0);
    free(reqBuf);
    return 0;
}

static int ShowConnectedDevList(char *buf, const int *size)
{
    return HostapdCliCmdListSta(g_hostapdHalDev->ctrlConn, buf, size);
}

static int ReloadApConfigInfo(void)
{
    char buf[BUFSIZE_REQUEST_SMALL] = {0};
    int retval = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, "RELOAD", buf, sizeof(buf));
    if (strncmp(buf, "OK", OK_LENTH) != 0) {
        retval = -1;
    }
    return retval;
}

static int CancelVerify(const char *mac)
{
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "DEAUTHENTICATE %s", mac) < 0) {
        return -1;
    }
    int retval = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
    if (strncmp(buf, "OK", OK_LENTH) != 0) {
        retval = -1;
    }
    return retval;
}

static int DisConnectedDev(const char *mac)
{
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "DISASSOCIATE %s", mac) < 0) {
        return -1;
    }
    int retval = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
    if (strncmp(buf, "OK", OK_LENTH) != 0) {
        retval = -1;
    }
    return retval;
}

static int SetCountryCode(const char *code)
{
    if (code == NULL) {
        return -1;
    }
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "SET country_code %s", code) < 0) {
        return -1;
    }
    int retval = WpaCtrlCommand(g_hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
    if (retval == 0) {
        if (strncmp(buf, "OK", OK_LENTH) != 0) {
            retval = -1;
            LOGE("set country code return [%{public}s]", buf);
        }
    } else {
        LOGE("SetCountryCode s failed. retval %{public}d", retval);
    }

    return retval;
}

static int InitHostapdHal(void)
{
    g_hostapdHalDev->threadRunFlag = 1;
    if (HostapdCliConnect()) {
        return -1;
    }
    return 0;
}

/* Open Device Function */
WifiHostapdHalDevice *GetWifiHostapdDev(void)
{
    if (g_hostapdHalDev != NULL) {
        return g_hostapdHalDev;
    }
    g_hostapdHalDev = (WifiHostapdHalDevice *)calloc(1, sizeof(WifiHostapdHalDevice));
    if (g_hostapdHalDev == NULL) {
        LOGE("NULL device on open");
        return NULL;
    }
    /* ************ hostapd_cli Interface Register************************* */
    g_hostapdHalDev->enableAp = EnableAp;
    g_hostapdHalDev->disableAp = DisableAp;
    g_hostapdHalDev->setApInfo = SetApInfo;
    g_hostapdHalDev->addBlocklist = AddBlocklist;
    g_hostapdHalDev->delBlocklist = DelBlocklist;
    g_hostapdHalDev->status = GetApStatus;
    g_hostapdHalDev->showConnectedDevList = ShowConnectedDevList;
    g_hostapdHalDev->reloadApConfigInfo = ReloadApConfigInfo;
    g_hostapdHalDev->cancelVerify = CancelVerify;
    g_hostapdHalDev->disConnectedDev = DisConnectedDev;
    g_hostapdHalDev->setCountryCode = SetCountryCode;
    if (InitHostapdHal()) {
        free(g_hostapdHalDev);
        g_hostapdHalDev = NULL;
        return NULL;
    }
    return g_hostapdHalDev;
}

void ReleaseHostapdDev(void)
{
    if (g_hostapdHalDev != NULL) {
        HostapdCliClose();
        free(g_hostapdHalDev);
        g_hostapdHalDev = NULL;
    }
}