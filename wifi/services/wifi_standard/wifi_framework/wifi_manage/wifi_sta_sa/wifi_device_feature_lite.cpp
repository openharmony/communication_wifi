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

#include <cstddef>
#include <cstdlib>

#include "iproxy_server.h"
#include "ohos_errno.h"
#include "ohos_init.h"
#include "samgr_lite.h"
#include "service.h"
#include "wifi_device_service_impl.h"
#include "wifi_log.h"
#include "wifi_ipc_lite_adapter.h"

using namespace OHOS::Wifi;

static std::shared_ptr<WifiDeviceServiceImpl> g_devServiceImpl = WifiDeviceServiceImpl::GetInstance();

typedef struct WifiDeviceApi {
    INHERIT_SERVER_IPROXY;
} WifiDeviceApi;

typedef struct WifiDeviceFeature {
    INHERIT_FEATURE;
    INHERIT_IUNKNOWNENTRY(WifiDeviceApi);
    Identity identity;
    Service *parent;
} WifiDeviceFeature;

static const char *GetName(Feature *feature)
{
    return WIFI_FEATURE_DEVICE;
}

static void OnInitialize(Feature *feature, Service *parent, Identity identity)
{
    if (feature != NULL) {
        WifiDeviceFeature *deviceFeature = (WifiDeviceFeature *)feature;
        deviceFeature->identity = identity;
        deviceFeature->parent = parent;
    }
    if (g_devServiceImpl != NULL) {
        g_devServiceImpl->OnStart();
    }
}

static void OnStop(Feature *feature, Identity identity)
{
    if (g_devServiceImpl != NULL) {
        g_devServiceImpl->OnStop();
    }
    if (feature != NULL) {
        WifiDeviceFeature *deviceFeature = (WifiDeviceFeature *)feature;
        deviceFeature->identity.queueId = NULL;
        deviceFeature->identity.featureId = -1;
        deviceFeature->identity.serviceId = -1;
    }
}

static BOOL OnMessage(Feature *feature, Request *request)
{
    return TRUE;
}

static int Invoke(IServerProxy *proxy, int funcId, void *origin, IpcIo *req, IpcIo *reply)
{
    LOGI("[WifiDeviceFeature] begin to call Invoke, funcId is %{public}d", funcId);
    if (g_devServiceImpl != NULL) {
        return g_devServiceImpl->OnRemoteRequest(funcId, req, reply);
    }
    return EC_FAILURE;
}

static WifiDeviceFeature g_devFeature = {
    .GetName = GetName,
    .OnInitialize = OnInitialize,
    .OnStop = OnStop,
    .OnMessage = OnMessage,
    SERVER_IPROXY_IMPL_BEGIN,
    .Invoke = Invoke,
    IPROXY_END,
    .identity = {-1, -1, NULL},
};

static void Init(void)
{
    LOGI("[WifiDeviceFeature] Init start.");
    BOOL ret = SAMGR_GetInstance()->RegisterFeature(WIFI_SERVICE_LITE, (Feature *)&g_devFeature);
    if (ret == FALSE) {
        LOGE("[WifiDeviceFeature] register feature fail.");
        return;
    }
    ret = SAMGR_GetInstance()->RegisterFeatureApi(WIFI_SERVICE_LITE,
        WIFI_FEATURE_DEVICE, GET_IUNKNOWN(g_devFeature));
    if (ret == FALSE) {
        LOGE("[WifiDeviceFeature] register feature api fail.");
    }
}
SYSEX_FEATURE_INIT(Init);
