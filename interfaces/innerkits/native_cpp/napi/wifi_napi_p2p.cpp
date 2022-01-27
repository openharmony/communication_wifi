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

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiNAPIP2p");

std::unique_ptr<WifiP2p> wifiP2pPtr = WifiP2p::GetInstance(WIFI_P2P_ABILITY_ID);

napi_value EnableP2p(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    NAPI_ASSERT(env, wifiP2pPtr != nullptr, "Wifi p2p instance is null.");

    ErrCode ret = wifiP2pPtr->EnableP2p();
    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

napi_value DisableP2p(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    NAPI_ASSERT(env, wifiP2pPtr != nullptr, "Wifi p2p instance is null.");

    ErrCode ret = wifiP2pPtr->DisableP2p();
    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

static void DeviceInfoToJs(const napi_env& env, const WifiP2pDevice& device, napi_value& result)
{
    SetValueUtf8String(env, "deviceName", device.GetDeviceName().c_str(), result);
    SetValueUtf8String(env, "macAddress", device.GetDeviceAddress().c_str(), result);
    SetValueUtf8String(env, "primaryDeviceType", device.GetPrimaryDeviceType().c_str(), result);
    SetValueUtf8String(env, "secondaryDeviceType", device.GetSecondaryDeviceType().c_str(), result);
    SetValueInt32(env, "status", static_cast<int>(device.GetP2pDeviceStatus()), result);
    SetValueUnsignedInt32(env, "supportWpsConfigMethods", device.GetWpsConfigMethod(), result);
    SetValueInt32(env, "deviceCapabilitys", device.GetDeviceCapabilitys(), result);
    SetValueInt32(env, "groupCapabilitys", device.GetGroupCapabilitys(), result);
}

static void WfdInfoToJs(const napi_env& env, const WifiP2pWfdInfo& wfdInfo, napi_value& result)
{
    SetValueBool(env, "wfdEnabled", wfdInfo.GetWfdEnabled(), result);
    SetValueInt32(env, "deviceInfo", wfdInfo.GetDeviceInfo(), result);
    SetValueInt32(env, "ctrlPort", wfdInfo.GetCtrlPort(), result);
    SetValueInt32(env, "maxThroughput", wfdInfo.GetMaxThroughput(), result);
}

static ErrCode DeviceInfosToJs(const napi_env& env,
    const std::vector<WifiP2pDevice>& vecDevices, napi_value& arrayResult)
{
    uint32_t idx = 0;
    for (auto& each : vecDevices) {
        napi_value eachObj;
        napi_create_object(env, &eachObj);
        DeviceInfoToJs(env, each, eachObj);
        WifiP2pWfdInfo info = each.GetWfdInfo();
        napi_value wfdInfo;
        napi_create_object(env, &wfdInfo);
        WfdInfoToJs(env, info, wfdInfo);
        napi_set_named_property(env, eachObj, "wfdInfo", wfdInfo);
        napi_status status = napi_set_element(env, arrayResult, idx++, eachObj);
        if (status != napi_ok) {
            WIFI_LOGE("wifi napi set element error: %{public}d, idx: %{public}d", status, idx - 1);
            return WIFI_OPT_FAILED;
        }
    }
    return WIFI_OPT_SUCCESS;
}

static ErrCode GroupInfosToJs(const napi_env& env, WifiP2pGroupInfo& groupInfo, napi_value& result)
{
    SetValueBool(env, "isP2pGroupOwner", groupInfo.IsGroupOwner(), result);
    SetValueUtf8String(env, "passphrase", groupInfo.GetPassphrase().c_str(), result);
    SetValueUtf8String(env, "interface", groupInfo.GetInterface().c_str(), result);
    SetValueUtf8String(env, "groupName", groupInfo.GetGroupName().c_str(), result);
    SetValueInt32(env, "networkId", groupInfo.GetNetworkId(), result);
    SetValueInt32(env, "frequency", groupInfo.GetFrequency(), result);
    SetValueBool(env, "isP2pPersistent", groupInfo.IsPersistent(), result);
    SetValueInt32(env, "groupStatus", static_cast<int>(groupInfo.GetP2pGroupStatus()), result);
    SetValueUtf8String(env, "goIpAddress", groupInfo.GetGoIpAddress().c_str(), result);

    WifiP2pDevice ownerDevice = groupInfo.GetOwner();
    napi_value owner;
    napi_create_object(env, &owner);
    DeviceInfoToJs(env, ownerDevice, owner);
    napi_status status = napi_set_named_property(env, result, "owner", owner);
    if (status != napi_ok) {
        WIFI_LOGE("napi_set_named_property owner fail");
        return WIFI_OPT_FAILED;
    }
    if (!groupInfo.IsClientDevicesEmpty()) {
        const std::vector<OHOS::Wifi::WifiP2pDevice>& vecDevices = groupInfo.GetClientDevices();
        napi_value devices;
        napi_create_array_with_length(env, vecDevices.size(), &devices);
        if (DeviceInfosToJs(env, vecDevices, devices) != WIFI_OPT_SUCCESS) {
            return WIFI_OPT_FAILED;
        }
        status = napi_set_named_property(env, result, "clientDevices", devices);
        if (status != napi_ok) {
            WIFI_LOGE("napi_set_named_property clientDevices fail");
            return WIFI_OPT_FAILED;
        }
    }
    return WIFI_OPT_SUCCESS;
}

napi_value GetCurrentGroup(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 2;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));

    P2pGroupInfoAsyncContext *asyncContext = new P2pGroupInfoAsyncContext(env);
    NAPI_ASSERT(env, asyncContext != nullptr, "asyncContext is null.");
    napi_create_string_latin1(env, "getCurrentGroup", NAPI_AUTO_LENGTH, &asyncContext->resourceName);

    asyncContext->executeFunc = [&](void* data) -> void {
        P2pGroupInfoAsyncContext *context = static_cast<P2pGroupInfoAsyncContext *>(data);
        TRACE_FUNC_CALL_NAME("wifiP2pPtr->GetCurrentGroup");
        context->errorCode = wifiP2pPtr->GetCurrentGroup(context->groupInfo);
    };

    asyncContext->completeFunc = [&](void* data) -> void {
        P2pGroupInfoAsyncContext *context = static_cast<P2pGroupInfoAsyncContext *>(data);
        napi_create_object(context->env, &context->result);
        context->errorCode = GroupInfosToJs(context->env, context->groupInfo, context->result);
        WIFI_LOGI("Push get current group result to client");
    };

    size_t nonCallbackArgNum = 0;
    return DoAsyncWork(env, asyncContext, argc, argv, nonCallbackArgNum);
}

napi_value StartP2pListen(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 2;
    napi_value argv[argc];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_valuetype valueType;
    napi_valuetype value2Type;
    napi_typeof(env, argv[0], &valueType);
    napi_typeof(env, argv[1], &value2Type);
    NAPI_ASSERT(env, valueType == napi_number, "Wrong argument 1 type. napi_number expected.");
    NAPI_ASSERT(env, value2Type == napi_object, "Wrong argument 2 type. napi_number expected.");

    NAPI_ASSERT(env, wifiP2pPtr != nullptr, "Wifi p2p instance is null.");
    int period;
    int interval;
    napi_get_value_int32(env, argv[0], &period);
    napi_get_value_int32(env, argv[1], &interval);
    ErrCode ret = wifiP2pPtr->StartP2pListen(period, interval);
    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

napi_value StopP2pListen(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    NAPI_ASSERT(env, wifiP2pPtr != nullptr, "Wifi p2p instance is null.");

    ErrCode ret = wifiP2pPtr->StopP2pListen();
    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

napi_value DeletePersistentGroup(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[argc];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "Wrong argument type. napi_number expected.");

    NAPI_ASSERT(env, wifiP2pPtr != nullptr, "Wifi p2p instance is null.");
    WifiP2pGroupInfo groupInfo;
    int netId = -999;
    napi_get_value_int32(env, argv[0], &netId);
    groupInfo.SetNetworkId(netId);
    ErrCode ret = wifiP2pPtr->DeleteGroup(groupInfo);
    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

napi_value StartDiscoverDevices(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    NAPI_ASSERT(env, wifiP2pPtr != nullptr, "Wifi p2p instance is null.");

    ErrCode ret = wifiP2pPtr->DiscoverDevices();
    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

napi_value StopDiscoverDevices(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    NAPI_ASSERT(env, wifiP2pPtr != nullptr, "Wifi p2p instance is null.");

    ErrCode ret = wifiP2pPtr->StopDiscoverDevices();
    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

napi_value GetP2pDevices(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    NAPI_ASSERT(env, wifiP2pPtr != nullptr, "Wifi p2p instance is null.");

    QueryP2pDeviceAsyncContext *asyncContext = new QueryP2pDeviceAsyncContext(env);
    NAPI_ASSERT(env, asyncContext != nullptr, "asyncContext is null.");
    napi_create_string_latin1(env, "queryP2pDevices", NAPI_AUTO_LENGTH, &asyncContext->resourceName);

    asyncContext->executeFunc = [&](void* data) -> void {
        QueryP2pDeviceAsyncContext *context = static_cast<QueryP2pDeviceAsyncContext *>(data);
        context->errorCode = wifiP2pPtr->QueryP2pDevices(context->vecP2pDevices);
        WIFI_LOGI("GetP2pDeviceList, size: %{public}zu", context->vecP2pDevices.size());
    };

    asyncContext->completeFunc = [&](void* data) -> void {
        QueryP2pDeviceAsyncContext *context = static_cast<QueryP2pDeviceAsyncContext *>(data);
        napi_create_array_with_length(context->env, context->vecP2pDevices.size(), &context->result);
        context->errorCode = DeviceInfosToJs(context->env, context->vecP2pDevices, context->result);
        WIFI_LOGI("Push P2p Device List to client");
    };

    size_t nonCallbackArgNum = 0;
    return DoAsyncWork(env, asyncContext, argc, argv, nonCallbackArgNum);
}

napi_value SetP2pDeviceName(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    NAPI_ASSERT(env, argc == 1, "Wrong number of arguments");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_string, "Wrong argument type. napi_number expected.");

    NAPI_ASSERT(env, wifiP2pPtr != nullptr, "Wifi p2p instance is null.");

    char name[64] = {0};
    size_t typeLen = 0;
    napi_get_value_string_utf8(env, argv[0], name, sizeof(name), &typeLen);
    ErrCode ret = wifiP2pPtr->SetP2pDeviceName(name);
    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

static void JsObjToP2pConfig(const napi_env& env, const napi_value& object, WifiP2pConfig& config)
{
    std::string address = "";
    int netId = -1;
    std::string passphrase = "";
    int groupOwnerIntent = -1;
    std::string groupName = "";
    int band = static_cast<int>(GroupOwnerBand::GO_BAND_AUTO);
    JsObjectToString(env, object, "macAddress", WIFI_MAC_LENGTH + 1, address);
    JsObjectToInt(env, object, "goBand", band);
    JsObjectToInt(env, object, "netId", netId);
    JsObjectToString(env, object, "passphrase", MAX_PASSPHRASE_LENGTH + 1, passphrase);
    JsObjectToInt(env, object, "groupOwnerIntent", groupOwnerIntent);
    JsObjectToString(env, object, "groupName", DEVICE_NAME_LENGTH + 1, groupName);
    config.SetDeviceAddress(address);
    config.SetGoBand(static_cast<GroupOwnerBand>(band));
    config.SetNetId(netId);
    config.SetPassphrase(passphrase);
    config.SetGroupOwnerIntent(groupOwnerIntent);
    config.SetGroupName(groupName);
}

napi_value P2pConnect(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[argc];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "Wrong argument type. Object expected.");

    NAPI_ASSERT(env, wifiP2pPtr != nullptr, "Wifi p2p instance is null.");
    WifiP2pConfig config;
    JsObjToP2pConfig(env, argv[0], config);
    ErrCode ret = wifiP2pPtr->P2pConnect(config);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Connect to device fail: %{public}d", ret);
    }
    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

napi_value P2pDisConnect(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    NAPI_ASSERT(env, wifiP2pPtr != nullptr, "Wifi p2p instance is null.");

    ErrCode ret = wifiP2pPtr->P2pDisConnect();
    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

napi_value CreateGroup(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "Wrong argument type. Object expected.");

    NAPI_ASSERT(env, wifiP2pPtr != nullptr, "Wifi p2p instance is null.");
    WifiP2pConfig config;
    JsObjToP2pConfig(env, argv[0], config);

    ErrCode ret = wifiP2pPtr->FormGroup(config);
    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

napi_value RemoveGroup(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    NAPI_ASSERT(env, wifiP2pPtr != nullptr, "Wifi p2p instance is null.");

    ErrCode ret = wifiP2pPtr->RemoveGroup();
    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

static void LinkedInfoToJs(const napi_env& env, WifiP2pLinkedInfo& linkedInfo, napi_value& result)
{
    SetValueInt32(env, "connectState", static_cast<int>(linkedInfo.GetConnectState()), result);
    SetValueBool(env, "isP2pGroupOwner", linkedInfo.IsGroupOwner(), result);
    SetValueUtf8String(env, "groupOwnerAddress", linkedInfo.GetGroupOwnerAddress().c_str(), result);
}

napi_value GetP2pLinkedInfo(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 2;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    NAPI_ASSERT(env, wifiP2pPtr != nullptr, "Wifi p2p instance is null.");

    P2pLinkedInfoAsyncContext *asyncContext = new P2pLinkedInfoAsyncContext(env);
    NAPI_ASSERT(env, asyncContext != nullptr, "asyncContext is null.");
    napi_create_string_latin1(env, "queryP2pLinkedInfo", NAPI_AUTO_LENGTH, &asyncContext->resourceName);

    asyncContext->executeFunc = [&](void* data) -> void {
        P2pLinkedInfoAsyncContext *context = static_cast<P2pLinkedInfoAsyncContext *>(data);
        TRACE_FUNC_CALL_NAME("wifiP2pPtr->QueryP2pLinkedInfo");
        context->errorCode = wifiP2pPtr->QueryP2pLinkedInfo(context->linkedInfo);
    };

    asyncContext->completeFunc = [&](void* data) -> void {
        P2pLinkedInfoAsyncContext *context = static_cast<P2pLinkedInfoAsyncContext *>(data);
        napi_create_object(context->env, &context->result);
        LinkedInfoToJs(context->env, context->linkedInfo, context->result);
        WIFI_LOGI("Push get linkedInfo result to client");
    };

    size_t nonCallbackArgNum = 0;
    return DoAsyncWork(env, asyncContext, argc, argv, nonCallbackArgNum);
}
}  // namespace Wifi
}  // namespace OHOS
