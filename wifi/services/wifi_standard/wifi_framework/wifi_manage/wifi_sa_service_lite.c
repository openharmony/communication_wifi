/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include <stddef.h>
#include <stdlib.h>

#include "iproxy_server.h"
#include "ohos_errno.h"
#include "ohos_init.h"
#include "samgr_lite.h"
#include "service.h"
#include "wifi_ipc_lite_adapter.h"
#include "wifi_log.h"

static const int STACK_SIZE = 0x800;
static const int QUEUE_SIZE = 20;

typedef struct WifiSaInterface {
    INHERIT_SERVER_IPROXY;
} WifiSaInterface;

typedef struct WifiSaService {
    INHERIT_SERVICE;
    INHERIT_IUNKNOWNENTRY(WifiSaInterface);
    Identity identity;
} WifiSaService;

static const char *GetName(Service *service)
{
    return WIFI_SERVICE_LITE;
}

static BOOL Initialize(Service *service, Identity identity)
{
    if (service == NULL) {
        return FALSE;
    }
    WifiSaService *wifiService = (WifiSaService *)service;
    wifiService->identity = identity;
    return TRUE;
}

static BOOL MessageHandle(Service *service, Request *msg)
{
    return TRUE;
}

static TaskConfig GetTaskConfig(Service *service)
{
    TaskConfig config = {LEVEL_HIGH, PRI_NORMAL, STACK_SIZE, QUEUE_SIZE, SINGLE_TASK};
    return config;
}

static int Invoke(IServerProxy *proxy, int funcId, void *origin, IpcIo *req, IpcIo *reply)
{
    LOGI("[WifiSaServer] begin to call Invoke, funcId is %{public}d", funcId);
    return EC_SUCCESS;
}

static WifiSaService g_wifiSaService = {
    .GetName = GetName,
    .Initialize = Initialize,
    .MessageHandle = MessageHandle,
    .GetTaskConfig = GetTaskConfig,
    SERVER_IPROXY_IMPL_BEGIN,
    .Invoke = Invoke,
    IPROXY_END,
};

static void Init(void)
{
    LOGI("[WifiSaServer] Init start.");
    BOOL ret;
    ret = SAMGR_GetInstance()->RegisterService((Service *)&g_wifiSaService);
    if (ret == FALSE) {
        LOGE("[WifiSaServer] register service fail.");
        return;
    }
    ret = SAMGR_GetInstance()->RegisterDefaultFeatureApi(WIFI_SERVICE_LITE, GET_IUNKNOWN(g_wifiSaService));
    if (ret == FALSE) {
        LOGE("[WifiSaServer] register default api fail.");
    }
}
SYSEX_SERVICE_INIT(Init);