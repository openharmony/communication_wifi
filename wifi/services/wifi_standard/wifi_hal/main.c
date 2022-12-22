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

#include <securec.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include "server.h"
#include "wifi_common_def.h"
#include "wifi_hal_adapter.h"
#include "wifi_hal_ap_interface.h"
#include "wifi_hal_crpc_server.h"
#include "wifi_hal_p2p_interface.h"
#include "wifi_hal_sta_interface.h"
#include "wifi_hostapd_hal.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "WifiHalService"

#define BUF_LEN 32
#define INVALID_PID (-1)
#define WIFI_SERVICE_NAME "wifi_manager_se"

static void SignalExit(int sig)
{
    LOGI("Caught signal %{public}d", sig);
    RpcServer *server = GetRpcServer();
    if (server != NULL) {
        StopEventLoop(server->loop);
    }
    return;
}

int GetWifiServicePid(void)
{
    char cmd[BUF_LEN];
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "pidof -s %s", WIFI_SERVICE_NAME) < 0) {
        return INVALID_PID;
    }

    FILE *p = popen(cmd, "r");
    if (!p) {
        return INVALID_PID;
    }
    const int base = 10;
    char buf[BUF_LEN];
    fgets(buf, BUF_LEN, p);
    pclose(p);
    return strtoul(buf, NULL, base);
}

static void SendStartNotify(void)
{
    int pid = GetWifiServicePid();
    if (pid <= 0) {
        LOGI("%{public}s is NOT running.", WIFI_SERVICE_NAME);
        return;
    }
    LOGI("Send SIGUSR1/2 SIG to pid %{public}d", pid);
    int ret = kill(pid, SIGUSR1);
    if (ret != 0) {
        LOGE("Send SIGUSR1 SIG to pid %{public}d failed: %{public}d", pid, ret);
    }
    ret = kill(pid, SIGUSR2);
    if (ret != 0) {
        LOGE("Send SIGUSR2 SIG to pid %{public}d failed: %{public}d", pid, ret);
    }
}

int main(void)
{
    LOGI("Wifi hal service starting...");
    char rpcSockPath[] = CONFIG_ROOR_DIR"/unix_sock.sock";
    if (access(rpcSockPath, 0) == 0) {
        unlink(rpcSockPath);
    }
    if (InitRpcFunc() < 0) {
        LOGE("Init Rpc Function failed!");
        return -1;
    }
    RpcServer *server = CreateRpcServer(rpcSockPath);
    if (server == NULL) {
        LOGE("Create RPC Server by %{public}s failed!", rpcSockPath);
        return -1;
    }
    SetRpcServerInited(server);
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGINT, SignalExit);
    signal(SIGTERM, SignalExit);
    signal(SIGPIPE, SIG_IGN);

    SendStartNotify();
    RunRpcLoop(server);
    /* stop wpa_supplicant, hostapd, and other resources */
    ForceStop();
    for (int id = 0; id < AP_MAX_INSTANCE; id++) {
        StopSoftAp(id);
    }
    P2pForceStop();
    ReleaseWifiHalVendorInterface();
    /* clear RPC Server */
    SetRpcServerInited(NULL);
    ReleaseRpcServer(server);
    ReleaseRpcFunc();
    LOGI("hal service exists!");
    return 0;
}
