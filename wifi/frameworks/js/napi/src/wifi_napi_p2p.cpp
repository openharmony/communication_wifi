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

#include "wifi_napi_p2p.h"
#include "wifi_logger.h"
#include "wifi_napi_errcode.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiNAPIP2p");

std::unique_ptr<WifiP2p> wifiP2pPtr = WifiP2p::GetInstance(WIFI_P2P_ABILITY_ID);
static void DeviceInfoToJs(const napi_env& env, const WifiP2pDevice& device, napi_value& result)
{
    SetValueUtf8String(env, "deviceName", device.GetDeviceName().c_str(), result);
    SetValueUtf8String(env, "deviceAddress", device.GetDeviceAddress().c_str(), result);
    SetValueUtf8String(env, "primaryDeviceType", device.GetPrimaryDeviceType().c_str(), result);
    SetValueInt32(env, "deviceStatus", static_cast<int>(device.GetP2pDeviceStatus()), result);
    SetValueInt32(env, "groupCapabilitys", device.GetGroupCapabilitys(), result);
}

static ErrCode DevicesToJsArray(const napi_env& env,
    const std::vector<WifiP2pDevice>& vecDevices, napi_value& arrayResult)
{
    uint32_t idx = 0;
    for (auto& each : vecDevices) {
        napi_value eachObj;
        napi_create_object(env, &eachObj);
        DeviceInfoToJs(env, each, eachObj);
        napi_status status = napi_set_element(env, arrayResult, idx++, eachObj);
        if (status != napi_ok) {
            WIFI_LOGE("wifi napi set element error: %{public}d, idx: %{public}d", status, idx - 1);
            return WIFI_OPT_FAILED;
        }
    }
    return WIFI_OPT_SUCCESS;
}

static ErrCode GroupInfosToJs(const napi_env& env, const WifiP2pGroupInfo& groupInfo, napi_value& result)
{
    SetValueBool(env, "isP2pGo", groupInfo.IsGroupOwner(), result);

    WifiP2pDevice ownerDevice = groupInfo.GetOwner();
    napi_value owner;
    napi_create_object(env, &owner);
    DeviceInfoToJs(env, ownerDevice, owner);
    napi_status status = napi_set_named_property(env, result, "ownerInfo", owner);
    if (status != napi_ok) {
        WIFI_LOGE("napi_set_named_property ownerInfo fail");
        return WIFI_OPT_FAILED;
    }

    SetValueUtf8String(env, "passphrase", groupInfo.GetPassphrase().c_str(), result);
    SetValueUtf8String(env, "interface", groupInfo.GetInterface().c_str(), result);
    SetValueUtf8String(env, "groupName", groupInfo.GetGroupName().c_str(), result);
    SetValueInt32(env, "networkId", groupInfo.GetNetworkId(), result);
    SetValueInt32(env, "frequency", groupInfo.GetFrequency(), result);

    if (!groupInfo.IsClientDevicesEmpty()) {
        const std::vector<OHOS::Wifi::WifiP2pDevice>& vecDevices = groupInfo.GetClientDevices();
        napi_value devices;
        napi_create_array_with_length(env, vecDevices.size(), &devices);
        if (DevicesToJsArray(env, vecDevices, devices) != WIFI_OPT_SUCCESS) {
            return WIFI_OPT_FAILED;
        }
        status = napi_set_named_property(env, result, "clientDevices", devices);
        if (status != napi_ok) {
            WIFI_LOGE("napi_set_named_property clientDevices fail");
            return WIFI_OPT_FAILED;
        }
    }
    SetValueUtf8String(env, "goIpAddress", groupInfo.GetGoIpAddress().c_str(), result);
    return WIFI_OPT_SUCCESS;
}

static ErrCode GroupsToJsArray(const napi_env& env,
    const std::vector<WifiP2pGroupInfo>& vecGroups, napi_value& arrayResult)
{
    uint32_t idx = 0;
    for (auto& each : vecGroups) {
        napi_value eachObj;
        napi_create_object(env, &eachObj);
        int ret = GroupInfosToJs(env, each, eachObj);
        if (ret != WIFI_OPT_SUCCESS) {
            return WIFI_OPT_FAILED;
        }
        napi_status status = napi_set_element(env, arrayResult, idx++, eachObj);
        if (status != napi_ok) {
            WIFI_LOGE("wifi napi set element error: %{public}d, idx: %{public}d", status, idx - 1);
            return WIFI_OPT_FAILED;
        }
    }
    return WIFI_OPT_SUCCESS;
}

napi_value GetCurrentGroup(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    WIFI_NAPI_ASSERT(env, wifiP2pPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);

    P2pGroupInfoAsyncContext *asyncContext = new P2pGroupInfoAsyncContext(env);
    WIFI_NAPI_ASSERT(env, asyncContext != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
    napi_create_string_latin1(env, "getCurrentGroup", NAPI_AUTO_LENGTH, &asyncContext->resourceName);

    asyncContext->executeFunc = [&](void* data) -> void {
        P2pGroupInfoAsyncContext *context = static_cast<P2pGroupInfoAsyncContext *>(data);
        TRACE_FUNC_CALL_NAME("wifiP2pPtr->GetCurrentGroup");
        context->errorCode = wifiP2pPtr->GetCurrentGroup(context->groupInfo);
    };

    asyncContext->completeFunc = [&](void* data) -> void {
        P2pGroupInfoAsyncContext *context = static_cast<P2pGroupInfoAsyncContext *>(data);
        napi_create_object(context->env, &context->result);
        if (context->errorCode == WIFI_OPT_SUCCESS) {
            context->errorCode = GroupInfosToJs(context->env, context->groupInfo, context->result);
        }
        WIFI_LOGI("Push get current group result to client");
    };

    size_t nonCallbackArgNum = 0;
    asyncContext->sysCap = SYSCAP_WIFI_P2P;
    return DoAsyncWork(env, asyncContext, argc, argv, nonCallbackArgNum);
}

napi_value GetP2pGroups(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    WIFI_NAPI_ASSERT(env, wifiP2pPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);

    P2pGroupInfoListAsyncContext *asyncContext = new P2pGroupInfoListAsyncContext(env);
    WIFI_NAPI_ASSERT(env, asyncContext != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
    napi_create_string_latin1(env, "GetP2pGroups", NAPI_AUTO_LENGTH, &asyncContext->resourceName);

    asyncContext->executeFunc = [&](void* data) -> void {
        P2pGroupInfoListAsyncContext *context = static_cast<P2pGroupInfoListAsyncContext *>(data);
        TRACE_FUNC_CALL_NAME("wifiP2pPtr->QueryP2pGroups");
        context->errorCode = wifiP2pPtr->QueryP2pGroups(context->vecGroupInfoList);
    };

    asyncContext->completeFunc = [&](void* data) -> void {
        P2pGroupInfoListAsyncContext *context = static_cast<P2pGroupInfoListAsyncContext *>(data);
        napi_create_array_with_length(context->env, context->vecGroupInfoList.size(), &context->result);
        if (context->errorCode == WIFI_OPT_SUCCESS) {
            context->errorCode = GroupsToJsArray(context->env, context->vecGroupInfoList, context->result);
        }
        WIFI_LOGI("Push get group info list to client");
    };

    size_t nonCallbackArgNum = 0;
    asyncContext->sysCap = SYSCAP_WIFI_P2P;
    return DoAsyncWork(env, asyncContext, argc, argv, nonCallbackArgNum);
}


napi_value DeletePersistentGroup(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[argc];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    WIFI_NAPI_ASSERT(env, wifiP2pPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_number, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_P2P);

    WifiP2pGroupInfo groupInfo;
    int netId = -999;
    napi_get_value_int32(env, argv[0], &netId);
    groupInfo.SetNetworkId(netId);
    ErrCode ret = wifiP2pPtr->DeleteGroup(groupInfo);
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_P2P);
}

napi_value StartDiscoverDevices(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiP2pPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);

    ErrCode ret = wifiP2pPtr->DiscoverDevices();
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_P2P);
}

napi_value StopDiscoverDevices(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiP2pPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);

    ErrCode ret = wifiP2pPtr->StopDiscoverDevices();
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_P2P);
}

napi_value GetP2pDevices(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    WIFI_NAPI_ASSERT(env, wifiP2pPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);

    QueryP2pDeviceAsyncContext *asyncContext = new QueryP2pDeviceAsyncContext(env);
    WIFI_NAPI_ASSERT(env, asyncContext != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
    napi_create_string_latin1(env, "GetP2pDevices", NAPI_AUTO_LENGTH, &asyncContext->resourceName);

    asyncContext->executeFunc = [&](void* data) -> void {
        QueryP2pDeviceAsyncContext *context = static_cast<QueryP2pDeviceAsyncContext *>(data);
        context->errorCode = wifiP2pPtr->QueryP2pDevices(context->vecP2pDevices);
        WIFI_LOGI("GetP2pDeviceList, size: %{public}zu", context->vecP2pDevices.size());
    };

    asyncContext->completeFunc = [&](void* data) -> void {
        QueryP2pDeviceAsyncContext *context = static_cast<QueryP2pDeviceAsyncContext *>(data);
        napi_create_array_with_length(context->env, context->vecP2pDevices.size(), &context->result);
        if (context->errorCode == WIFI_OPT_SUCCESS) {
            context->errorCode = DevicesToJsArray(context->env, context->vecP2pDevices, context->result);
        }
        WIFI_LOGI("Push P2p Device List to client");
    };

    size_t nonCallbackArgNum = 0;
    asyncContext->sysCap = SYSCAP_WIFI_P2P;
    return DoAsyncWork(env, asyncContext, argc, argv, nonCallbackArgNum);
}

napi_value GetP2pLocalDevice(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    WIFI_NAPI_ASSERT(env, wifiP2pPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);

    P2pLocalDeviceAsyncContext *asyncContext = new P2pLocalDeviceAsyncContext(env);
    WIFI_NAPI_ASSERT(env, asyncContext != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
    napi_create_string_latin1(env, "GetP2pLocalDevice", NAPI_AUTO_LENGTH, &asyncContext->resourceName);

    asyncContext->executeFunc = [&](void* data) -> void {
        P2pLocalDeviceAsyncContext *context = static_cast<P2pLocalDeviceAsyncContext *>(data);
        TRACE_FUNC_CALL_NAME("wifiP2pPtr->QueryP2pLocalDevice");
        context->errorCode = wifiP2pPtr->QueryP2pLocalDevice(context->deviceInfo);
    };

    asyncContext->completeFunc = [&](void* data) -> void {
        P2pLocalDeviceAsyncContext *context = static_cast<P2pLocalDeviceAsyncContext *>(data);
        napi_create_object(context->env, &context->result);
        if (context->errorCode == WIFI_OPT_SUCCESS) {
            DeviceInfoToJs(context->env, context->deviceInfo, context->result);
        }
        WIFI_LOGI("Push get p2p local device result to client");
    };

    size_t nonCallbackArgNum = 0;
    asyncContext->sysCap = SYSCAP_WIFI_P2P;
    return DoAsyncWork(env, asyncContext, argc, argv, nonCallbackArgNum);
}

napi_value SetDeviceName(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    WIFI_NAPI_ASSERT(env, argc == 1, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_P2P);
    WIFI_NAPI_ASSERT(env, wifiP2pPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_string, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_P2P);

    char name[64] = {0};
    size_t typeLen = 0;
    napi_get_value_string_utf8(env, argv[0], name, sizeof(name), &typeLen);
    ErrCode ret = wifiP2pPtr->SetP2pDeviceName(name);
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_P2P);
}

static void JsObjToP2pConfig(const napi_env& env, const napi_value& object, WifiP2pConfig& config)
{
    std::string address = "";
    int netId = -1;
    std::string passphrase = "";
    std::string groupName = "";
    int band = static_cast<int>(GroupOwnerBand::GO_BAND_AUTO);
    JsObjectToString(env, object, "deviceAddress", WIFI_STR_MAC_LENGTH + 1, address);
    JsObjectToInt(env, object, "netId", netId);
    JsObjectToString(env, object, "passphrase", MAX_PASSPHRASE_LENGTH + 1, passphrase);
    JsObjectToString(env, object, "groupName", DEVICE_NAME_LENGTH + 1, groupName);
    JsObjectToInt(env, object, "goBand", band);
    config.SetDeviceAddress(address);
    config.SetNetId(netId);
    config.SetPassphrase(passphrase);
    config.SetGroupName(groupName);
    config.SetGoBand(static_cast<GroupOwnerBand>(band));
}

napi_value P2pConnect(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[argc];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    WIFI_NAPI_ASSERT(env, wifiP2pPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_object, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_P2P);

    WifiP2pConfig config;
    JsObjToP2pConfig(env, argv[0], config);
    ErrCode ret = wifiP2pPtr->P2pConnect(config);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Connect to device fail: %{public}d", ret);
    }
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_P2P);
}

napi_value P2pCancelConnect(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiP2pPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
    ErrCode ret = wifiP2pPtr->P2pCancelConnect();
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_P2P);
}

napi_value CreateGroup(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    WIFI_NAPI_ASSERT(env, wifiP2pPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_object, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_P2P);

    WifiP2pConfig config;
    JsObjToP2pConfig(env, argv[0], config);
    ErrCode ret = wifiP2pPtr->CreateGroup(config);
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_P2P);
}

napi_value RemoveGroup(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiP2pPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
    ErrCode ret = wifiP2pPtr->RemoveGroup();
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_P2P);
}

static void LinkedInfoToJs(const napi_env& env, WifiP2pLinkedInfo& linkedInfo, napi_value& result)
{
    SetValueInt32(env, "connectState", static_cast<int>(linkedInfo.GetConnectState()), result);
    SetValueBool(env, "isGroupOwner", linkedInfo.IsGroupOwner(), result);
    SetValueUtf8String(env, "groupOwnerAddr", linkedInfo.GetGroupOwnerAddress().c_str(), result);
}

napi_value GetP2pLinkedInfo(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    WIFI_NAPI_ASSERT(env, wifiP2pPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);

    P2pLinkedInfoAsyncContext *asyncContext = new P2pLinkedInfoAsyncContext(env);
    WIFI_NAPI_ASSERT(env, asyncContext != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
    napi_create_string_latin1(env, "queryP2pLinkedInfo", NAPI_AUTO_LENGTH, &asyncContext->resourceName);

    asyncContext->executeFunc = [&](void* data) -> void {
        P2pLinkedInfoAsyncContext *context = static_cast<P2pLinkedInfoAsyncContext *>(data);
        TRACE_FUNC_CALL_NAME("wifiP2pPtr->QueryP2pLinkedInfo");
        context->errorCode = wifiP2pPtr->QueryP2pLinkedInfo(context->linkedInfo);
    };

    asyncContext->completeFunc = [&](void* data) -> void {
        P2pLinkedInfoAsyncContext *context = static_cast<P2pLinkedInfoAsyncContext *>(data);
        napi_create_object(context->env, &context->result);
        if (context->errorCode == WIFI_OPT_SUCCESS) {
            LinkedInfoToJs(context->env, context->linkedInfo, context->result);
        }
        WIFI_LOGI("Push get linkedInfo result to client");
    };

    size_t nonCallbackArgNum = 0;
    asyncContext->sysCap = SYSCAP_WIFI_P2P;
    return DoAsyncWork(env, asyncContext, argc, argv, nonCallbackArgNum);
}
}  // namespace Wifi
}  // namespace OHOS
