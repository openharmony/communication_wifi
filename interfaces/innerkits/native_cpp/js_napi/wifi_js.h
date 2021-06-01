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

#ifndef WIFI_JS_TYPE_H_
#define WIFI_JS_TYPE_H_

#include <string>
#include "napi/native_api.h"
#include "napi/native_node_api.h"

enum WifiSecurityType {
    WIFI_SEC_TYPE_INVALID = 0, /* Invalid security type */
    WIFI_SEC_TYPE_OPEN = 1, /* Open */
    WIFI_SEC_TYPE_WEP = 2, /* Wired Equivalent Privacy (WEP) */
    WIFI_SEC_TYPE_PSK = 3, /* Pre-shared key (PSK) */
    WIFI_SEC_TYPE_SAE = 4, /* Simultaneous Authentication of Equals (SAE) */
};

class JsWifiDeviceConfig {
public:
    std::string ssid;
    std::string bssid;
    std::string preSharedKey;
    bool isHiddenSsid;
    int securityType;

    JsWifiDeviceConfig() {
        isHiddenSsid = false;
        securityType = WIFI_SEC_TYPE_INVALID;
    }
    virtual ~JsWifiDeviceConfig() {
    }
};

class JsWifiScanInfo {
public:
    std::string ssid;
    std::string bssid;
    int securityType;
    int rssi;
    int band;
    int frequency;
    long timestamp;

    JsWifiScanInfo() {
        securityType = WIFI_SEC_TYPE_INVALID;
        rssi = 0;
        band = 0;
        frequency = 0;
        timestamp = 0;
    }
    virtual ~JsWifiScanInfo() {
    }
};

struct AsyncCallbackInfo {
    napi_env env;
    napi_async_work asyncWork;
    napi_deferred deferred;
    napi_ref callback[2] = { 0 };
    void *obj;
    napi_value result;
    bool isSuccess;
};

#endif
