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

#ifdef HDI_INTERFACE_SUPPORT
#include "wifi_hdi_proxy.h"
#include <stdlib.h>
#include <pthread.h>
#include "wifi_log.h"
#include "servmgr_hdi.h"
#include "hdf_remote_service.h"
#include "osal_mem.h"

#undef LOG_TAG
#define LOG_TAG "WifiHdiProxy"

#define MAX_FEATURE_NUMBER 16
#define MAX_OBJ_REFERENCE_COUNT 2
#define MAX_IFACENAME_LEN 16
const char *HDI_SERVICE_NAME = "wlan_interface_service"; // Move the define to HDF module

static pthread_mutex_t g_mutex;
static unsigned int g_wlanRefCount = 0;
static struct IWlanInterface *g_wlanObj = NULL;
static struct HdfFeatureInfo* g_featureArray[MAX_FEATURE_NUMBER] = {NULL};
static bool g_isRemoteDied = false;
static pthread_mutex_t g_wlanIfaceNameMutex = PTHREAD_MUTEX_INITIALIZER;
static char g_wlanIfaceName[MAX_IFACENAME_LEN] = {0};

static WifiErrorNo ReleaseFeatureInner(const int32_t wlanType)
{
    WifiErrorNo ret = WIFI_IDL_OPT_OK;
    if (g_wlanObj == NULL) {
        LOGE("%{public}s g_wlanObj is null", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    for (int i = 0; i != MAX_FEATURE_NUMBER; ++i) {
        if (g_featureArray[i] == NULL || g_featureArray[i]->type != wlanType) {
            continue;
        }
        LOGI("%{public}s destory feature begin.", __func__);
        ret = g_wlanObj->DestroyFeature(g_wlanObj, g_featureArray[i]);
        if (ret != HDF_SUCCESS) {
            LOGE("Destroy feature %{public}d failed: %{public}d", g_featureArray[i]->type, ret);
        }
        LOGI("%{public}s destory feature end.", __func__);
        free(g_featureArray[i]);
        g_featureArray[i] = NULL;
        break;
    }
    return ret;
}

static struct HdfFeatureInfo* GetFeatureInner(const int32_t wlanType)
{
    struct HdfFeatureInfo *feature = NULL;
    if (g_wlanObj == NULL) {
        LOGE("%{public}s: g_wlanObj is null, wlanType:%{public}d", __func__, wlanType);
        return NULL;
    }
    for (int i = 0; i != MAX_FEATURE_NUMBER; ++i) {
        if (g_featureArray[i] == NULL) {
            continue;
        }
        if (g_featureArray[i]->type == wlanType) {
            LOGD("%{public}s: get an exist feature, wlanType:%{public}d", __func__, wlanType);
            feature = g_featureArray[i];
            return feature;
        }
    }

    /* allocate 1 struct */
    feature = (struct HdfFeatureInfo *)calloc(1, sizeof(struct HdfFeatureInfo));
    if (feature == NULL) {
        LOGE("%{public}s: failed to alloc memory", __func__);
        return NULL;
    }
    LOGI("%{public}s: Create feature type: %{public}d", __func__, wlanType);
    int32_t ret = g_wlanObj->CreateFeature(g_wlanObj, wlanType, feature);
    if (ret != HDF_SUCCESS) {
        LOGE("CreateFeature %{public}d failed: %{public}d", wlanType, ret);
        goto FAILURE;
    }
    LOGI("%{public}s: success to create feature, ifname:%{public}s", __func__, feature->ifName);
    bool isAdd = false;
    for (int i = 0; i != MAX_FEATURE_NUMBER; ++i) {
        if (g_featureArray[i] == NULL) {
            g_featureArray[i] = feature;
            isAdd = true;
            break;
        }
    }
    if (!isAdd) {
        LOGE("%{public}s: g_featureArray is full!", __func__);
        goto FAILURE;
    }
    return feature;

FAILURE:
    if (feature != NULL) {
        free(feature);
    }
    return NULL;
}

static void ReleaseAllFeatures()
{
    if (g_wlanObj == NULL) {
        return;
    }
    WifiErrorNo ret = WIFI_IDL_OPT_OK;
    for (int i = 0; i != MAX_FEATURE_NUMBER; ++i) {
        if (g_featureArray[i] == NULL) {
            continue;
        }
        LOGI("%{public}s destory feature[all] begin.", __func__);
        ret = g_wlanObj->DestroyFeature(g_wlanObj, g_featureArray[i]);
        if (ret != HDF_SUCCESS) {
            LOGE("Destroy feature %{public}d failed: %{public}d", g_featureArray[i]->type, ret);
        }
        LOGI("%{public}s destory feature[all] end.", __func__);
        free(g_featureArray[i]);
        g_featureArray[i] = NULL;
    }
}

static void ProxyOnRemoteDied(struct HdfDeathRecipient* recipient, struct HdfRemoteService* service)
{
    LOGI("%{public}s enter", __func__);
    if (recipient == NULL || service == NULL) {
        LOGE("%{public}s input param is null", __func__);
        return;
    }
    g_isRemoteDied = true;
    CleanLocalResources();
    HdfRemoteServiceRemoveDeathRecipient(service, recipient);
    HdfRemoteServiceRecycle(service);
    if (recipient != NULL) {
        OsalMemFree(recipient);
        recipient = NULL;
    }
}

WifiErrorNo StartHdiWifi()
{
    LOGI("%{public}s: begin to start hdi service", __func__);
    pthread_mutex_lock(&g_mutex);
    if (g_wlanRefCount != 0) {
        ++g_wlanRefCount;
        if (g_wlanRefCount > MAX_OBJ_REFERENCE_COUNT) {
            g_wlanRefCount = MAX_OBJ_REFERENCE_COUNT;
        }
        pthread_mutex_unlock(&g_mutex);
        LOGI("%{public}s: wlan ref count:%{public}d", __func__, g_wlanRefCount);
        return WIFI_IDL_OPT_OK;
    }
    g_wlanObj = IWlanInterfaceGetInstance(HDI_SERVICE_NAME, false);
    if (g_wlanObj == NULL) {
        pthread_mutex_unlock(&g_mutex);
        LOGE("%{public}s: failed to get instance", __func__);
        return WIFI_IDL_OPT_FAILED;
    } else {
        LOGI("%{public}s: success to create the hdi WlanInterface, wlanObj:%{public}p", __func__, g_wlanObj);
    }
    int32_t ret = g_wlanObj->Start(g_wlanObj);
    if (ret != HDF_SUCCESS) {
        LOGE("%{public}s: failed to start wlan, ret:%{public}d", __func__, ret);
        IWlanInterfaceReleaseInstance(HDI_SERVICE_NAME, g_wlanObj, false);
        g_wlanObj = NULL;
        pthread_mutex_unlock(&g_mutex);
        return WIFI_IDL_OPT_FAILED;
    }
    g_isRemoteDied = false;
    ++g_wlanRefCount;
    pthread_mutex_unlock(&g_mutex);
    LOGI("%{public}s: success to start wlan", __func__);

    struct HDIServiceManager* serviceMgr = HDIServiceManagerGet();
    if (serviceMgr == NULL) {
        LOGE("%{public}s: failed to get HDIServiceManager", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    struct HdfRemoteService* remote = serviceMgr->GetService(serviceMgr, HDI_SERVICE_NAME);
    HDIServiceManagerRelease(serviceMgr);
    if (remote == NULL) {
        LOGE("%{public}s: failed to get HdfRemoteService", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    LOGI("%{public}s: success to get HdfRemoteService", __func__);
    struct HdfDeathRecipient* recipient = (struct HdfDeathRecipient*)OsalMemCalloc(sizeof(struct HdfDeathRecipient));
    if (recipient == NULL) {
        LOGE("%{public}s: OsalMemCalloc is failed", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    recipient->OnRemoteDied = ProxyOnRemoteDied;
    HdfRemoteServiceAddDeathRecipient(remote, recipient);
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiStop()
{
    LOGI("%{public}s: begin to stop hdi service", __func__);
    pthread_mutex_lock(&g_mutex);
    if (g_wlanObj == NULL) {
        pthread_mutex_unlock(&g_mutex);
        LOGE("%{public}s: parameter null, no need to stop.", __func__);
        return WIFI_IDL_OPT_OK;
    }

    const unsigned int ONE_REF_COUNT = 1;
    if (g_wlanRefCount > ONE_REF_COUNT) {
        --g_wlanRefCount;
        pthread_mutex_unlock(&g_mutex);
        LOGI("%{public}s: invalid wlanRefCount:%{public}d", __func__, g_wlanRefCount);
        return WIFI_IDL_OPT_OK;
    }
    ReleaseAllFeatures();
    int32_t ret = g_wlanObj->Stop(g_wlanObj);
    if (ret != HDF_SUCCESS) {
        LOGE("%{public}s: failed to stop, ret:%{public}d", __func__, ret);
    }
    IWlanInterfaceReleaseInstance(HDI_SERVICE_NAME, g_wlanObj, false);
    g_wlanRefCount = 0;
    g_wlanObj = NULL;
    pthread_mutex_unlock(&g_mutex);
    LOGI("%{public}s: success to release instance", __func__);
    return (ret == HDF_SUCCESS) ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo IsHdiStopped()
{
    pthread_mutex_lock(&g_mutex);
    if (g_wlanObj == NULL && g_wlanRefCount == 0) {
        LOGI("Hdi already stopped");
        pthread_mutex_unlock(&g_mutex);
        return WIFI_IDL_OPT_OK;
    }

    pthread_mutex_unlock(&g_mutex);
    return WIFI_IDL_OPT_FAILED;
}

struct IWlanInterface* GetWlanInterface()
{
    struct IWlanInterface *wlanObj = NULL;
    pthread_mutex_lock(&g_mutex);
    wlanObj = g_wlanObj;
    pthread_mutex_unlock(&g_mutex);
    return wlanObj;
}

WifiHdiProxy GetHdiProxy(const int32_t wlanType)
{
    WifiHdiProxy proxy = {.wlanObj = NULL, .feature = NULL};
    pthread_mutex_lock(&g_mutex);
    struct HdfFeatureInfo* feature = GetFeatureInner(wlanType);
    if (feature == NULL) {
        pthread_mutex_unlock(&g_mutex);
        LOGE("%{public}s GetFeature failed!", __func__);
        return proxy;
    }
    proxy.wlanObj = g_wlanObj;
    proxy.feature = feature;
    pthread_mutex_unlock(&g_mutex);
    return proxy;
}

WifiErrorNo ReleaseHdiProxy(const int32_t wlanType)
{
    WifiErrorNo ret = WIFI_IDL_OPT_FAILED;
    pthread_mutex_lock(&g_mutex);
    ret = ReleaseFeatureInner(wlanType);
    pthread_mutex_unlock(&g_mutex);
    return ret;
}

bool IsHdiRemoteDied()
{
    return g_isRemoteDied;
}

void CleanLocalResources()
{
    pthread_mutex_lock(&g_mutex);
    ReleaseAllFeatures();
    IWlanInterfaceReleaseInstance(HDI_SERVICE_NAME, g_wlanObj, false);
    g_wlanObj = NULL;
    g_wlanRefCount = 0;
    pthread_mutex_unlock(&g_mutex);
}

WifiErrorNo CheckHdiNormalStart(const int32_t wlanType)
{
    WifiErrorNo ret = WIFI_IDL_OPT_OK;
    WifiHdiProxy proxy = GetHdiProxy(wlanType);
    if (proxy.wlanObj == NULL || proxy.feature == NULL) {
        LOGE("CheckHdiNormalStart: Hdi proxy is null, hdi abnormal start!");
        ret = IsHdiStopped();
        if (ret != WIFI_IDL_OPT_OK) {
            ret = HdiStop();
            if (ret != WIFI_IDL_OPT_OK) {
                LOGE("CheckHdiNormalStart: HdiStop failed!");
                return ret;
            }
            ret = StartHdiWifi();
            if (ret != WIFI_IDL_OPT_OK) {
                LOGE("CheckHdiNormalStart: StartHdiWifi failed!");
                return ret;
            }
        }
    }
    LOGI("CheckHdiNormalStart: hdi normal start!");
    return ret;
}

WifiErrorNo SetWifiHdiStaIfaceName(const char *ifaceName)
{
    pthread_mutex_lock(&g_wlanIfaceNameMutex);
    if (ifaceName == NULL) {
        pthread_mutex_unlock(&g_wlanIfaceNameMutex);
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    if (memset_s(g_wlanIfaceName, MAX_IFACENAME_LEN, 0, MAX_IFACENAME_LEN) != EOK) {
        pthread_mutex_unlock(&g_wlanIfaceNameMutex);
        return WIFI_IDL_OPT_FAILED;
    }

    if (strcpy_s(g_wlanIfaceName, MAX_IFACENAME_LEN, ifaceName) != EOK) {
        pthread_mutex_unlock(&g_wlanIfaceNameMutex);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("SetWifiHdiStaIfaceName, g_wlanIfaceName:%{public}s", g_wlanIfaceName);
    pthread_mutex_unlock(&g_wlanIfaceNameMutex);
    return WIFI_IDL_OPT_OK;
}

const char *GetWifiHdiStaIfaceName()
{
    const char *ifaceName = NULL;
    pthread_mutex_lock(&g_wlanIfaceNameMutex);
    ifaceName = g_wlanIfaceName;
    pthread_mutex_unlock(&g_wlanIfaceNameMutex);
    return ifaceName;
}
#endif
