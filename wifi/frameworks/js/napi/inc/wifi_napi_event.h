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

#ifndef WIFI_NAPI_EVENT_H_
#define WIFI_NAPI_EVENT_H_

#include <string>
#include <set>
#include <map>
#include "napi/native_api.h"
#include "wifi_errcode.h"
#include <shared_mutex>
#include "wifi_p2p.h"
#include "wifi_hotspot.h"
#include "wifi_logger.h"
#include "wifi_sa_event.h"

DEFINE_WIFILOG_LABEL("WifiNapiEvent");

namespace OHOS {
namespace Wifi {
class RegObj {
public:
    RegObj() : m_regEnv(0), m_regHanderRef(nullptr) {
    }
    explicit RegObj(const napi_env& env, const napi_ref& ref) {
        m_regEnv = env;
        m_regHanderRef = ref;
    }

    ~RegObj() {
    }

    bool operator == (const RegObj& other) const {
        return m_regEnv == other.m_regEnv && m_regHanderRef == other.m_regHanderRef;
    }

    bool operator != (const RegObj& other) const {
        return !(*this == other);
    }

    bool operator < (const RegObj& other) const {
        return m_regEnv < other.m_regEnv || (m_regEnv == other.m_regEnv && m_regHanderRef < other.m_regHanderRef);
    }

    napi_env m_regEnv;
    napi_ref m_regHanderRef;
};

class AsyncEventData {
public:
    napi_env env;
    napi_ref callbackRef;
    std::function<napi_value ()> packResult;
    std::string eventType;

    explicit AsyncEventData(napi_env e, napi_ref r, std::function<napi_value ()> p, const std::string& type)
    {
        env = e;
        callbackRef = r;
        packResult = p;
        eventType = type;
    }

    AsyncEventData() = delete;

    virtual ~AsyncEventData() {
    }
};

static std::shared_mutex g_regInfoMutex;
static std::map<std::string, std::vector<RegObj>> g_eventRegisterInfo;

class NapiEvent {
public:
    napi_value CreateResult(const napi_env& env, int value);
    napi_value CreateResult(const napi_env& env, const StationInfo& info);
    napi_value CreateResult(const napi_env& env, napi_value placehoders);
    napi_value CreateResult(const napi_env& env, const WifiP2pDevice& device);
    napi_value CreateResult(const napi_env& env, const std::vector<WifiP2pDevice>& devices);
    napi_value CreateResult(const napi_env& env, const WifiP2pLinkedInfo& info);
    void EventNotify(AsyncEventData *asyncEvent);

    template<typename T>
    void CheckAndNotify(const std::string& type, const T& obj) {
        std::shared_lock<std::shared_mutex> guard(g_regInfoMutex);
        auto it = g_eventRegisterInfo.find(type);
        if (it == g_eventRegisterInfo.end()) {
            WIFI_LOGW("not find register info.");
            return;
        }
        for (auto& each : it->second) {
            auto func = [this, env = each.m_regEnv, obj] () -> napi_value { return CreateResult(env, obj); };
            AsyncEventData *asyncEvent = new (std::nothrow)AsyncEventData(each.m_regEnv, each.m_regHanderRef,
                func, type);
            if (asyncEvent == nullptr) {
                return;
            }
            EventNotify(asyncEvent);
        }
    }
};

class WifiNapiAbilityStatusChange : public WifiAbilityStatusChange {
public:
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
};

class EventRegister {
public:
    EventRegister()
    {
        int32_t ret;
        auto samgrProxy = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            WIFI_LOGI("samgrProxy is nullptr!");
            return;
        }
        mSaStatusListener = new OHOS::Wifi::WifiNapiAbilityStatusChange();
        if (mSaStatusListener == nullptr) {
            WIFI_LOGI("mSaStatusListener is nullptr!");
            return;
        }
        ret = samgrProxy->SubscribeSystemAbility((int32_t)WIFI_DEVICE_ABILITY_ID, mSaStatusListener);
        samgrProxy->SubscribeSystemAbility((int32_t)WIFI_SCAN_ABILITY_ID, mSaStatusListener);
        samgrProxy->SubscribeSystemAbility((int32_t)WIFI_HOTSPOT_ABILITY_ID, mSaStatusListener);
        samgrProxy->SubscribeSystemAbility((int32_t)WIFI_P2P_ABILITY_ID, mSaStatusListener);
        WIFI_LOGI("EventRegister, SubscribeSystemAbility return ret:%{public}d!", ret);
    }
    ~EventRegister() {
    }

    static EventRegister& GetInstance();

    void Register(const napi_env& env, const std::string& type, napi_value handler);
    void Unregister(const napi_env& env, const std::string& type, napi_value handler);
    ErrCode RegisterDeviceEvents(const std::vector<std::string> &event);
    ErrCode RegisterScanEvents(const std::vector<std::string> &event);
    ErrCode RegisterHotspotEvents(const std::vector<std::string> &event);
    ErrCode RegisterP2PEvents(const std::vector<std::string> &event);

private:
    ErrCode RegisterWifiEvents(int32_t sysCap, const std::string& type);
    bool IsEventSupport(const std::string& type);
    void DeleteRegisterObj(const napi_env& env, std::vector<RegObj>& vecRegObjs, napi_value& handler);
    void DeleteAllRegisterObj(const napi_env& env, std::vector<RegObj>& vecRegObjs);
    OHOS::sptr<OHOS::ISystemAbilityStatusChange> mSaStatusListener = nullptr;
};

napi_value On(napi_env env, napi_callback_info cbinfo);
napi_value Off(napi_env env, napi_callback_info cbinfo);
}  // namespace Wifi
}  // namespace OHOS

#endif
