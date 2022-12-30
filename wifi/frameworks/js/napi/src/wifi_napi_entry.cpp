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

#include "wifi_napi_device.h"
#include "wifi_napi_hotspot.h"
#include "wifi_napi_p2p.h"
#include "wifi_napi_event.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
#ifndef ENABLE_NAPI_COMPATIBLE

static napi_value SuppStateInit(napi_env env)
{
    napi_value suppState = nullptr;
    napi_create_object(env, &suppState);
    SetNamedPropertyByInteger(env, suppState, static_cast<int>(SuppStateJs::DISCONNECTED), "DISCONNECTED");
    SetNamedPropertyByInteger(env, suppState, static_cast<int>(SuppStateJs::INTERFACE_DISABLED), "INTERFACE_DISABLED");
    SetNamedPropertyByInteger(env, suppState, static_cast<int>(SuppStateJs::INACTIVE), "INACTIVE");
    SetNamedPropertyByInteger(env, suppState, static_cast<int>(SuppStateJs::SCANNING), "SCANNING");
    SetNamedPropertyByInteger(env, suppState, static_cast<int>(SuppStateJs::AUTHENTICATING), "AUTHENTICATING");
    SetNamedPropertyByInteger(env, suppState, static_cast<int>(SuppStateJs::ASSOCIATING), "ASSOCIATING");
    SetNamedPropertyByInteger(env, suppState, static_cast<int>(SuppStateJs::ASSOCIATED), "ASSOCIATED");
    SetNamedPropertyByInteger(env, suppState, static_cast<int>(SuppStateJs::FOUR_WAY_HANDSHAKE), "FOUR_WAY_HANDSHAKE");
    SetNamedPropertyByInteger(env, suppState, static_cast<int>(SuppStateJs::GROUP_HANDSHAKE), "GROUP_HANDSHAKE");
    SetNamedPropertyByInteger(env, suppState, static_cast<int>(SuppStateJs::COMPLETED), "COMPLETED");
    SetNamedPropertyByInteger(env, suppState, static_cast<int>(SuppStateJs::UNINITIALIZED), "UNINITIALIZED");
    SetNamedPropertyByInteger(env, suppState, static_cast<int>(SuppStateJs::INVALID), "INVALID");
    return suppState;
}

static napi_value SecurityTypeInit(napi_env env)
{
    napi_value securityType = nullptr;
    napi_create_object(env, &securityType);
    SetNamedPropertyByInteger(env, securityType,
        static_cast<int>(SecTypeJs::SEC_TYPE_INVALID), "WIFI_SEC_TYPE_INVALID");
    SetNamedPropertyByInteger(env, securityType, static_cast<int>(SecTypeJs::SEC_TYPE_OPEN), "WIFI_SEC_TYPE_OPEN");
    SetNamedPropertyByInteger(env, securityType, static_cast<int>(SecTypeJs::SEC_TYPE_WEP), "WIFI_SEC_TYPE_WEP");
    SetNamedPropertyByInteger(env, securityType, static_cast<int>(SecTypeJs::SEC_TYPE_PSK), "WIFI_SEC_TYPE_PSK");
    SetNamedPropertyByInteger(env, securityType, static_cast<int>(SecTypeJs::SEC_TYPE_SAE), "WIFI_SEC_TYPE_SAE");
#ifdef ENABLE_NAPI_WIFI_MANAGER
    SetNamedPropertyByInteger(env, securityType, static_cast<int>(SecTypeJs::SEC_TYPE_EAP), "WIFI_SEC_TYPE_EAP");
    SetNamedPropertyByInteger(env, securityType,
        static_cast<int>(SecTypeJs::SEC_TYPE_EAP_SUITE_B), "WIFI_SEC_TYPE_EAP_SUITE_B");
    SetNamedPropertyByInteger(env, securityType, static_cast<int>(SecTypeJs::SEC_TYPE_OWE), "WIFI_SEC_TYPE_OWE");
    SetNamedPropertyByInteger(env, securityType,
        static_cast<int>(SecTypeJs::SEC_TYPE_WAPI_CERT), "WIFI_SEC_TYPE_WAPI_CERT");
    SetNamedPropertyByInteger(env, securityType,
        static_cast<int>(SecTypeJs::SEC_TYPE_WAPI_PSK), "WIFI_SEC_TYPE_WAPI_PSK");
#endif
    return securityType;
}

static napi_value IpTypeInit(napi_env env)
{
    napi_value IpType = nullptr;
    napi_create_object(env, &IpType);
    SetNamedPropertyByInteger(env, IpType, static_cast<int>(IpTypeJs::IP_TYPE_STATIC), "STATIC");
    SetNamedPropertyByInteger(env, IpType, static_cast<int>(IpTypeJs::IP_TYPE_DHCP), "DHCP");
    SetNamedPropertyByInteger(env, IpType, static_cast<int>(IpTypeJs::IP_TYPE_UNKNOWN), "UNKNOWN");
    return IpType;
}

static napi_value ConnStateInit(napi_env env)
{
    napi_value connState = nullptr;
    napi_create_object(env, &connState);
    SetNamedPropertyByInteger(env, connState, static_cast<int>(ConnStateJs::SCANNING), "SCANNING");
    SetNamedPropertyByInteger(env, connState, static_cast<int>(ConnStateJs::CONNECTING), "CONNECTING");
    SetNamedPropertyByInteger(env, connState, static_cast<int>(ConnStateJs::AUTHENTICATING), "AUTHENTICATING");
    SetNamedPropertyByInteger(env, connState, static_cast<int>(ConnStateJs::OBTAINING_IPADDR), "OBTAINING_IPADDR");
    SetNamedPropertyByInteger(env, connState, static_cast<int>(ConnStateJs::CONNECTED), "CONNECTED");
    SetNamedPropertyByInteger(env, connState, static_cast<int>(ConnStateJs::DISCONNECTING), "DISCONNECTING");
    SetNamedPropertyByInteger(env, connState, static_cast<int>(ConnStateJs::DISCONNECTED), "DISCONNECTED");
    SetNamedPropertyByInteger(env, connState, static_cast<int>(ConnStateJs::UNKNOWN), "UNKNOWN");
    return connState;
}


static napi_value P2pConnStateInit(napi_env env)
{
    napi_value p2pConnState = nullptr;
    napi_create_object(env, &p2pConnState);
    SetNamedPropertyByInteger(env, p2pConnState, static_cast<int>(P2pConnectStateJs::DISCONNECTED), "DISCONNECTED");
    SetNamedPropertyByInteger(env, p2pConnState, static_cast<int>(P2pConnectStateJs::CONNECTED), "CONNECTED");
    return p2pConnState;
}

static napi_value P2pDeviceStatusInit(napi_env env)
{
    napi_value p2pDeviceStatus = nullptr;
    napi_create_object(env, &p2pDeviceStatus);
    SetNamedPropertyByInteger(env, p2pDeviceStatus, static_cast<int>(P2pDeviceStatusJs::CONNECTED), "CONNECTED");
    SetNamedPropertyByInteger(env, p2pDeviceStatus, static_cast<int>(P2pDeviceStatusJs::INVITED), "INVITED");
    SetNamedPropertyByInteger(env, p2pDeviceStatus, static_cast<int>(P2pDeviceStatusJs::FAILED), "FAILED");
    SetNamedPropertyByInteger(env, p2pDeviceStatus, static_cast<int>(P2pDeviceStatusJs::AVAILABLE), "AVAILABLE");
    SetNamedPropertyByInteger(env, p2pDeviceStatus, static_cast<int>(P2pDeviceStatusJs::UNAVAILABLE), "UNAVAILABLE");
    return p2pDeviceStatus;
}

static napi_value GroupOwnerBandInit(napi_env env)
{
    napi_value groupOwnerBand = nullptr;
    napi_create_object(env, &groupOwnerBand);
    SetNamedPropertyByInteger(env, groupOwnerBand, static_cast<int>(GroupOwnerBandJs::GO_BAND_AUTO), "GO_BAND_AUTO");
    SetNamedPropertyByInteger(env, groupOwnerBand, static_cast<int>(GroupOwnerBandJs::GO_BAND_2GHZ), "GO_BAND_2GHZ");
    SetNamedPropertyByInteger(env, groupOwnerBand, static_cast<int>(GroupOwnerBandJs::GO_BAND_5GHZ), "GO_BAND_5GHZ");
    return groupOwnerBand;
}

#ifdef ENABLE_NAPI_WIFI_MANAGER
static napi_value Phase2MethodInit(napi_env env)
{
    napi_value phase2Method = nullptr;
    napi_create_object(env, &phase2Method);
    SetNamedPropertyByInteger(env, phase2Method, static_cast<int>(Phase2MethodJs::PHASE2_NONE), "PHASE2_NONE");
    SetNamedPropertyByInteger(env, phase2Method, static_cast<int>(Phase2MethodJs::PHASE2_PAP), "PHASE2_PAP");
    SetNamedPropertyByInteger(env, phase2Method, static_cast<int>(Phase2MethodJs::PHASE2_MSCHAP), "PHASE2_MSCHAP");
    SetNamedPropertyByInteger(env, phase2Method, static_cast<int>(Phase2MethodJs::PHASE2_MSCHAPV2), "PHASE2_MSCHAPV2");
    SetNamedPropertyByInteger(env, phase2Method, static_cast<int>(Phase2MethodJs::PHASE2_GTC), "PHASE2_GTC");
    SetNamedPropertyByInteger(env, phase2Method, static_cast<int>(Phase2MethodJs::PHASE2_SIM), "PHASE2_SIM");
    SetNamedPropertyByInteger(env, phase2Method, static_cast<int>(Phase2MethodJs::PHASE2_AKA), "PHASE2_AKA");
    SetNamedPropertyByInteger(env, phase2Method,
        static_cast<int>(Phase2MethodJs::PHASE2_AKA_PRIME), "PHASE2_AKA_PRIME");
    return phase2Method;
}
static napi_value WifiChannelWidthInit(napi_env env)
{
    napi_value wifiChannelWidth = nullptr;
    napi_create_object(env, &wifiChannelWidth);
    SetNamedPropertyByInteger(env, wifiChannelWidth, static_cast<int>(WifiChannelWidthJs::WIDTH_20MHZ), "WIDTH_20MHZ");
    SetNamedPropertyByInteger(env, wifiChannelWidth, static_cast<int>(WifiChannelWidthJs::WIDTH_40MHZ), "WIDTH_40MHZ");
    SetNamedPropertyByInteger(env, wifiChannelWidth, static_cast<int>(WifiChannelWidthJs::WIDTH_80MHZ), "WIDTH_80MHZ");
    SetNamedPropertyByInteger(env, wifiChannelWidth,
        static_cast<int>(WifiChannelWidthJs::WIDTH_160MHZ), "WIDTH_160MHZ");
    SetNamedPropertyByInteger(env, wifiChannelWidth,
        static_cast<int>(WifiChannelWidthJs::WIDTH_80MHZ_PLUS), "WIDTH_80MHZ_PLUS");
    SetNamedPropertyByInteger(env, wifiChannelWidth,
        static_cast<int>(WifiChannelWidthJs::WIDTH_INVALID), "WIDTH_INVALID");
    return wifiChannelWidth;
}

static napi_value EapMethodInit(napi_env env)
{
    napi_value eapMethod = nullptr;
    napi_create_object(env, &eapMethod);
    SetNamedPropertyByInteger(env, eapMethod, static_cast<int>(EapMethodJs::EAP_NONE), "EAP_NONE");
    SetNamedPropertyByInteger(env, eapMethod, static_cast<int>(EapMethodJs::EAP_PEAP), "EAP_PEAP");
    SetNamedPropertyByInteger(env, eapMethod, static_cast<int>(EapMethodJs::EAP_TLS), "EAP_TLS");
    SetNamedPropertyByInteger(env, eapMethod, static_cast<int>(EapMethodJs::EAP_TTLS), "EAP_TTLS");
    SetNamedPropertyByInteger(env, eapMethod, static_cast<int>(EapMethodJs::EAP_PWD), "EAP_PWD");
    SetNamedPropertyByInteger(env, eapMethod, static_cast<int>(EapMethodJs::EAP_SIM), "EAP_SIM");
    SetNamedPropertyByInteger(env, eapMethod, static_cast<int>(EapMethodJs::EAP_AKA), "EAP_AKA");
    SetNamedPropertyByInteger(env, eapMethod, static_cast<int>(EapMethodJs::EAP_AKA_PRIME), "EAP_AKA_PRIME");
    SetNamedPropertyByInteger(env, eapMethod, static_cast<int>(EapMethodJs::EAP_UNAUTH_TLS), "EAP_UNAUTH_TLS");
    return eapMethod;
}
#endif

static napi_value PropertyValueInit(napi_env env, napi_value exports)
{
    napi_value suppStateObj = SuppStateInit(env);
    napi_value securityTypeObj = SecurityTypeInit(env);
    napi_value ipTypeObj = IpTypeInit(env);
    napi_value connStateObj = ConnStateInit(env);
    napi_value p2pConnStateObj = P2pConnStateInit(env);
    napi_value P2pDeviceStatusObj = P2pDeviceStatusInit(env);
    napi_value groupOwnerBandObj = GroupOwnerBandInit(env);
#ifdef ENABLE_NAPI_WIFI_MANAGER
    napi_value phase2MethodObj = Phase2MethodInit(env);
    napi_value WifiChannelWidthObj = WifiChannelWidthInit(env);
    napi_value EapMethodObj = EapMethodInit(env);
#endif
    napi_property_descriptor exportFuncs[] = {
#ifdef ENABLE_NAPI_WIFI_MANAGER
        DECLARE_NAPI_PROPERTY("Phase2Method", phase2MethodObj),
        DECLARE_NAPI_PROPERTY("WifiChannelWidth", WifiChannelWidthObj),
        DECLARE_NAPI_PROPERTY("EapMethod", EapMethodObj),
#endif
        DECLARE_NAPI_PROPERTY("SuppState", suppStateObj),
        DECLARE_NAPI_PROPERTY("WifiSecurityType", securityTypeObj),
        DECLARE_NAPI_PROPERTY("IpType", ipTypeObj),
        DECLARE_NAPI_PROPERTY("ConnState", connStateObj),
        DECLARE_NAPI_PROPERTY("P2pConnectState", p2pConnStateObj),
        DECLARE_NAPI_PROPERTY("P2pDeviceStatus", P2pDeviceStatusObj),
        DECLARE_NAPI_PROPERTY("GroupOwnerBand", groupOwnerBandObj),
    };
    napi_define_properties(env, exports, sizeof(exportFuncs) / sizeof(napi_property_descriptor), exportFuncs);
    return exports;
}
/*
 * Module initialization function
 */
static napi_value Init(napi_env env, napi_value exports) {
    PropertyValueInit(env, exports);
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("enableWifi", EnableWifi),
        DECLARE_NAPI_FUNCTION("disableWifi", DisableWifi),
        DECLARE_NAPI_FUNCTION("isWifiActive", IsWifiActive),
        DECLARE_NAPI_FUNCTION("scan", Scan),
        DECLARE_NAPI_FUNCTION("getScanInfos", GetScanInfos),
        DECLARE_NAPI_FUNCTION("getScanInfosSync", GetScanResults),
        DECLARE_NAPI_FUNCTION("getScanResults", GetScanInfos),
        DECLARE_NAPI_FUNCTION("getScanResultsSync", GetScanResults),
        DECLARE_NAPI_FUNCTION("addDeviceConfig", AddDeviceConfig),
        DECLARE_NAPI_FUNCTION("addUntrustedConfig", AddUntrustedConfig),
        DECLARE_NAPI_FUNCTION("removeUntrustedConfig", RemoveUntrustedConfig),
        DECLARE_NAPI_FUNCTION("addCandidateConfig", AddCandidateConfig),
        DECLARE_NAPI_FUNCTION("removeCandidateConfig", RemoveCandidateConfig),
        DECLARE_NAPI_FUNCTION("connectToCandidateConfig", ConnectToCandidateConfig),
        DECLARE_NAPI_FUNCTION("getCandidateConfigs", GetCandidateConfigs),
        DECLARE_NAPI_FUNCTION("connectToNetwork", ConnectToNetwork),
        DECLARE_NAPI_FUNCTION("connectToDevice", ConnectToDevice),
        DECLARE_NAPI_FUNCTION("isConnected", IsConnected),
        DECLARE_NAPI_FUNCTION("disconnect", Disconnect),
        DECLARE_NAPI_FUNCTION("getSignalLevel", GetSignalLevel),
        DECLARE_NAPI_FUNCTION("reconnect", ReConnect),
        DECLARE_NAPI_FUNCTION("reassociate", ReAssociate),
        DECLARE_NAPI_FUNCTION("getIpInfo", GetIpInfo),
        DECLARE_NAPI_FUNCTION("getLinkedInfo", GetLinkedInfo),
        DECLARE_NAPI_FUNCTION("removeDevice", RemoveDevice),
        DECLARE_NAPI_FUNCTION("removeAllNetwork", RemoveAllNetwork),
        DECLARE_NAPI_FUNCTION("disableNetwork", DisableNetwork),
        DECLARE_NAPI_FUNCTION("getCountryCode", GetCountryCode),
        DECLARE_NAPI_FUNCTION("getDeviceConfigs", GetDeviceConfigs),
        DECLARE_NAPI_FUNCTION("updateNetwork", UpdateNetwork),
        DECLARE_NAPI_FUNCTION("getSupportedFeatures", GetSupportedFeatures),
        DECLARE_NAPI_FUNCTION("isFeatureSupported", IsFeatureSupported),
        DECLARE_NAPI_FUNCTION("getDeviceMacAddress", GetDeviceMacAddress),
        DECLARE_NAPI_FUNCTION("isHotspotActive", IsHotspotActive),
        DECLARE_NAPI_FUNCTION("isHotspotDualBandSupported", IsHotspotDualBandSupported),
        DECLARE_NAPI_FUNCTION("enableHotspot", EnableHotspot),
        DECLARE_NAPI_FUNCTION("disableHotspot", DisableHotspot),
        DECLARE_NAPI_FUNCTION("setHotspotConfig", SetHotspotConfig),
        DECLARE_NAPI_FUNCTION("getHotspotConfig", GetHotspotConfig),
        DECLARE_NAPI_FUNCTION("getStations", GetStations),
        DECLARE_NAPI_FUNCTION("addBlockList", AddBlockList),
        DECLARE_NAPI_FUNCTION("delBlockList", DelBlockList),
        DECLARE_NAPI_FUNCTION("getP2pLinkedInfo", GetP2pLinkedInfo),
        DECLARE_NAPI_FUNCTION("getCurrentGroup", GetCurrentGroup),
        DECLARE_NAPI_FUNCTION("getP2pPeerDevices", GetP2pDevices),
        DECLARE_NAPI_FUNCTION("getP2pLocalDevice", GetP2pLocalDevice),
        DECLARE_NAPI_FUNCTION("createGroup", CreateGroup),
        DECLARE_NAPI_FUNCTION("removeGroup", RemoveGroup),
        DECLARE_NAPI_FUNCTION("p2pConnect", P2pConnect),
        DECLARE_NAPI_FUNCTION("p2pCancelConnect", P2pCancelConnect),
        DECLARE_NAPI_FUNCTION("p2pDisconnect", P2pCancelConnect),
        DECLARE_NAPI_FUNCTION("startDiscoverDevices", StartDiscoverDevices),
        DECLARE_NAPI_FUNCTION("stopDiscoverDevices", StopDiscoverDevices),
        DECLARE_NAPI_FUNCTION("deletePersistentGroup", DeletePersistentGroup),
        DECLARE_NAPI_FUNCTION("getP2pGroups", GetP2pGroups),
        DECLARE_NAPI_FUNCTION("setDeviceName", SetDeviceName),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("off", Off),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(napi_property_descriptor), desc));
    return exports;
}

static napi_module wifiJsModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = NULL,
    .nm_register_func = Init,
#ifdef ENABLE_NAPI_WIFI_MANAGER
    .nm_modname = "wifiManager",
#else
    .nm_modname = "wifi",
#endif
    .nm_priv = ((void *)0),
    .reserved = { 0 }
};

#else

/*
 * Module initialization function
 */
static napi_value InitForCompatible(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("enableWifi", EnableWifi),
        DECLARE_NAPI_FUNCTION("disableWifi", DisableWifi),
        DECLARE_NAPI_FUNCTION("isWifiActive", IsWifiActive),
        DECLARE_NAPI_FUNCTION("scan", Scan),
        DECLARE_NAPI_FUNCTION("getScanInfos", GetScanInfos),
        DECLARE_NAPI_FUNCTION("addDeviceConfig", AddDeviceConfig),
        DECLARE_NAPI_FUNCTION("connectToNetwork", ConnectToNetwork),
        DECLARE_NAPI_FUNCTION("connectToDevice", ConnectToDevice),
        DECLARE_NAPI_FUNCTION("disconnect", Disconnect),
        DECLARE_NAPI_FUNCTION("getSignalLevel", GetSignalLevel),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(napi_property_descriptor), desc));
    return exports;
}

/* @Deprecated - Changeme module name from "wifi_native_js" to "wifi",
 * "wifi_native_js" will be discarded. Modify @11/2021
 */
static napi_module wifiJsModuleForCompatible = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = NULL,
    .nm_register_func = InitForCompatible,
    .nm_modname = "wifi_native_js",
    .nm_priv = ((void *)0),
    .reserved = { 0 }
};
#endif

extern "C" __attribute__((constructor)) void RegisterModule(void) {
#ifndef ENABLE_NAPI_COMPATIBLE
    napi_module_register(&wifiJsModule);
#else
    napi_module_register(&wifiJsModuleForCompatible);
#endif
}
}  // namespace Wifi
}  // namespace OHOS
