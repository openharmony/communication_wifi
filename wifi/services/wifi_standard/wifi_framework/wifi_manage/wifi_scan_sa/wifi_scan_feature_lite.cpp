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
#include "wifi_log.h"
#include "wifi_ipc_lite_adapter.h"
#include "wifi_scan_service_impl.h"

using namespace OHOS::Wifi;

static std::shared_ptr<WifiScanServiceImpl> g_scanServiceImpl = WifiScanServiceImpl::GetInstance();

typedef struct WifiScanApi {
    INHERIT_SERVER_IPROXY;
} WifiScanApi;

typedef struct WifiScanFeature {
    INHERIT_FEATURE;
    INHERIT_IUNKNOWNENTRY(WifiScanApi);
    Identity identity;
    Service *parent;
} WifiScanFeature;

static const char *GetName(Feature *feature)
{
    return WIFI_FEATRUE_SCAN;
}

static void OnInitialize(Feature *feature, Service *parent, Identity identity)
{
    if (feature != NULL) {
        WifiScanFeature *scanFeature = (WifiScanFeature *)feature;
        scanFeature->identity = identity;
        scanFeature->parent = parent;
    }
    if (g_scanServiceImpl != NULL) {
        g_scanServiceImpl->OnStart();
    }
}

static void OnStop(Feature *feature, Identity identity)
{
    if (g_scanServiceImpl != NULL) {
        g_scanServiceImpl->OnStop();
    }
    if (feature != NULL) {
        WifiScanFeature *scanFeature = (WifiScanFeature *)feature;
        scanFeature->identity.queueId = NULL;
        scanFeature->identity.featureId = -1;
        scanFeature->identity.serviceId = -1;
    }
}

static BOOL OnMessage(Feature *feature, Request *request)
{
    return TRUE;
}

static int Invoke(IServerProxy *proxy, int funcId, void *origin, IpcIo *req, IpcIo *reply)
{
    LOGI("[WifiScanFeature] begin to call Invoke, funcId is %{public}d", funcId);
    if (g_scanServiceImpl != NULL) {
        return g_scanServiceImpl->OnRemoteRequest(funcId, req, reply);
    }
    return EC_FAILURE;
}

static WifiScanFeature g_scanFeature = {
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
    LOGI("[WifiScanFeature] Init start.");
    BOOL ret = SAMGR_GetInstance()->RegisterFeature(WIFI_SERVICE_LITE, (Feature *)&g_scanFeature);
    if (ret == FALSE) {
        LOGE("[WifiScanFeature] register feature fail.");
        return;
    }
    ret = SAMGR_GetInstance()->RegisterFeatureApi(WIFI_SERVICE_LITE,
        WIFI_FEATRUE_SCAN, GET_IUNKNOWN(g_scanFeature));
    if (ret == FALSE) {
        LOGE("[WifiScanFeature] register feature api fail.");
    }
}
SYSEX_FEATURE_INIT(Init);
