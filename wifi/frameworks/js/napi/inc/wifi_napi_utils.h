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

#ifndef WIFI_NAPI_UTILS_H_
#define WIFI_NAPI_UTILS_H_

#include <string>
#include <chrono>
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Wifi {
static constexpr int NAPI_MAX_STR_LENT = 128;
static const std::int32_t SYSCAP_WIFI_CORE = 2400000;
static const std::int32_t SYSCAP_WIFI_STA = 2500000;
static const std::int32_t SYSCAP_WIFI_AP_CORE = 2600000;
static const std::int32_t SYSCAP_WIFI_AP_EXT = 2700000;
static const std::int32_t SYSCAP_WIFI_P2P = 2800000;

class TraceFuncCall final {
public:
    TraceFuncCall(std::string funcName);

    TraceFuncCall() = delete;

    ~TraceFuncCall();

private:
    std::string m_funcName;
    std::chrono::steady_clock::time_point m_startTime;
    bool m_isTrace = true;
};

#define TRACE_FUNC_CALL TraceFuncCall func(__func__)
#define TRACE_FUNC_CALL_NAME(name) TraceFuncCall funcName(name)

constexpr int ERR_CODE_SUCCESS = 0;

class AsyncContext {
public:
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callback[2] = { 0 };
    std::function<void(void*)> executeFunc;
    std::function<void(void*)> completeFunc;
    napi_value resourceName;
    napi_value result;
    int32_t sysCap;
    int errorCode;

    AsyncContext(napi_env e, napi_async_work w = nullptr, napi_deferred d = nullptr)
    {
        env = e;
        work = w;
        deferred = d;
        executeFunc = nullptr;
        completeFunc = nullptr;
        result = nullptr;
        sysCap = 0;
        errorCode = ERR_CODE_SUCCESS;
    }

    AsyncContext() = delete;

    virtual ~AsyncContext()
    {
    }
};

napi_value UndefinedNapiValue(const napi_env& env);
napi_value CreateInt32(const napi_env& env);
napi_value JsObjectToString(const napi_env& env, const napi_value& object,
    const char* fieldStr, const int bufLen, std::string& fieldRef);
napi_value JsObjectToInt(const napi_env& env, const napi_value& object, const char* fieldStr, int& fieldRef);
napi_value JsObjectToUint(const napi_env& env, const napi_value& object, const char* fieldStr, uint32_t& fieldRef);
napi_value JsObjectToBool(const napi_env& env, const napi_value& object, const char* fieldStr, bool& fieldRef);
std::vector<uint8_t> JsObjectToU8Vector(const napi_env& env, const napi_value& object, const char* fieldStr);
napi_status SetValueUtf8String(const napi_env& env, const char* fieldStr, const char* str,
    napi_value& result, size_t strLen = NAPI_AUTO_LENGTH);
napi_status SetValueUtf8String(const napi_env& env, const std::string &fieldStr, const std::string &valueStr,
    napi_value& result);
napi_status SetValueInt32(const napi_env& env, const char* fieldStr, const int intValue, napi_value& result);
napi_status SetValueUnsignedInt32(const napi_env& env, const char* fieldStr, const int intValue,
    napi_value& result);
napi_status SetValueInt64(const napi_env& env, const char* fieldStr, const int64_t intValue, napi_value& result);
napi_status SetValueBool(const napi_env& env, const char* fieldStr, const bool boolValue, napi_value& result);
napi_value DoAsyncWork(const napi_env& env, AsyncContext *asyncContext,
    const size_t argc, const napi_value *argv, const size_t nonCallbackArgNum);
void SetNamedPropertyByInteger(napi_env, napi_value dstObj, int32_t objName, const char *propName);

enum class SecTypeJs {
    /** Invalid security type */
    SEC_TYPE_INVALID = 0,
    /** Open */
    SEC_TYPE_OPEN = 1,
    /** Wired Equivalent Privacy (WEP) */
    SEC_TYPE_WEP = 2,
    /** Pre-shared key (PSK) */
    SEC_TYPE_PSK = 3,
    /** Simultaneous Authentication of Equals (SAE) */
    SEC_TYPE_SAE = 4,
    /** EAP authentication. */
    SEC_TYPE_EAP = 5,
#ifdef ENABLE_NAPI_WIFI_MANAGER
    /** SUITE_B_192 192 bit level. */
    SEC_TYPE_EAP_SUITE_B = 6,
    /** Opportunistic Wireless Encryption. */
    SEC_TYPE_OWE = 7,
    /** WAPI certificate to be specified. */
    SEC_TYPE_WAPI_CERT = 8,
    /** WAPI pre-shared key to be specified. */
    SEC_TYPE_WAPI_PSK = 9,
#endif
};

enum class EapMethodJs {
    EAP_NONE = 0,
    EAP_PEAP = 1,
    EAP_TLS = 2,
    EAP_TTLS = 3,
    EAP_PWD = 4,
    EAP_SIM = 5,
    EAP_AKA = 6,
    EAP_AKA_PRIME = 7,
    EAP_UNAUTH_TLS = 8,
};

enum class ConnStateJs {
    SCANNING, /* The device is searching for an available AP */
    CONNECTING, /* The Wi-Fi connection is being set up */
    AUTHENTICATING, /* The Wi-Fi connection is being authenticated */
    OBTAINING_IPADDR, /* The IP address of the Wi-Fi connection is being obtained */
    CONNECTED, /* The Wi-Fi connection has been set up */
    DISCONNECTING, /* The Wi-Fi connection is being torn down */
    DISCONNECTED, /* The Wi-Fi connection has been torn down */
    UNKNOWN /* Failed to set up the Wi-Fi connection */
};

enum class SuppStateJs {
    DISCONNECTED = 0, /* The network interface is disabled. */
    INTERFACE_DISABLED, /* The supplicant is disabled. */
    INACTIVE, /* The supplicant is scanning for a Wi-Fi connection. */
    SCANNING, /* The supplicant is authenticating with a specified AP. */
    AUTHENTICATING, /* The supplicant is associating with a specified AP. */
    ASSOCIATING, /* The supplicant is associated with a specified AP. */
    ASSOCIATED, /* The four-way handshake is ongoing. */
    FOUR_WAY_HANDSHAKE, /* The group handshake is ongoing. */
    GROUP_HANDSHAKE, /* All authentication is completed. */
    COMPLETED, /* Failed to establish a connection to the supplicant. */
    UNINITIALIZED, /* The supplicant is in an unknown or invalid state. */
    INVALID,
};

enum class IpTypeJs {
    /** Use statically configured IP settings */
    IP_TYPE_STATIC,
    /** Use dynamically configured IP settings */
    IP_TYPE_DHCP,
    /** No IP details are assigned */
    IP_TYPE_UNKNOWN,
};

enum class P2pConnectStateJs {
    DISCONNECTED = 0,
    CONNECTED = 1,
};

enum class P2pDeviceStatusJs {
    CONNECTED = 0,
    INVITED = 1,
    FAILED = 2,
    AVAILABLE = 3,
    UNAVAILABLE = 4,
};

enum class GroupOwnerBandJs {
    GO_BAND_AUTO = 0,
    GO_BAND_2GHZ = 1,
    GO_BAND_5GHZ = 2,
};

enum class Phase2MethodJs {
    PHASE2_NONE,
    PHASE2_PAP,
    PHASE2_MSCHAP,
    PHASE2_MSCHAPV2,
    PHASE2_GTC,
    PHASE2_SIM,
    PHASE2_AKA,
    PHASE2_AKA_PRIME,
};

enum class WifiChannelWidthJs {
    WIDTH_20MHZ = 0,
    WIDTH_40MHZ = 1,
    WIDTH_80MHZ = 2,
    WIDTH_160MHZ = 3,
    WIDTH_80MHZ_PLUS = 4,
    WIDTH_INVALID,
};

enum class PowerModelJs {
    SLEEPING = 0,
    GENERAL = 1,
    THROUGH_WALL = 2,
};
}  // namespace Wifi
}  // namespace OHOS

#endif
