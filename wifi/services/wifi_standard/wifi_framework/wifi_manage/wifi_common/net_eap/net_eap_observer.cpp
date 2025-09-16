/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "net_eap_observer.h"
#include <unistd.h>
#include <pthread.h>
#include <thread>
#include <sstream>
#include "wifi_common_util.h"
#include "wifi_logger.h"
#include "wifi_errcode.h"

DEFINE_WIFILOG_LABEL("WifiNetEapObserver");

namespace OHOS {
namespace Wifi {

NetEapObserver::NetEapObserver()
{
    WIFI_LOGD("construct NetEapObserver");
    netEapCallback_ = sptr<NetEapCallback>(new NetEapCallback());
}

NetEapObserver::~NetEapObserver()
{
    WIFI_LOGD("~NetEapObserver");
}

NetEapObserver &NetEapObserver::GetInstance()
{
    static NetEapObserver obj;
    return obj;
}

bool NetEapObserver::SetRegisterCustomEapCallback(const std::function<void(const std::string &)> &callback)
{
    if (netEapCallback_ == nullptr) {
        WIFI_LOGE("%{public}s, netEapCallback_ is nullptr", __func__);
        return false;
    }
    return netEapCallback_->SetRegisterCustomEapCallback(callback);
}

bool NetEapObserver::SetReplyCustomEapDataCallback(const std::function<void(int, const std::string&)> &callback)
{
    if (netEapCallback_ == nullptr) {
        WIFI_LOGE("%{public}s, netEapCallback_ is nullptr", __func__);
        return false;
    }
    return netEapCallback_->SetReplyCustomEapDataCallback(callback);
}

bool NetEapObserver::StartNetEapObserver()
{
    int32_t ret = DelayedSingleton<NetManagerStandard::EthernetClient>::GetInstance()->RegisterCustomEapCallback(
        NetManagerStandard::NetType::WLAN0, netEapCallback_);
    if (ret == NetManagerStandard::NETMANAGER_SUCCESS) {
        WIFI_LOGI("StartNetEapObserver register success");
        return true;
    }
    WIFI_LOGI("StartNetEapObserver failed, ret=%{public}d", ret);
    return false;
}

bool NetEapObserver::StopNetEapObserver()
{
    int32_t ret = DelayedSingleton<NetManagerStandard::EthernetClient>::GetInstance()->UnRegisterCustomEapCallback(
        NetManagerStandard::NetType::WLAN0, netEapCallback_);
    if (ret == NetManagerStandard::NETMANAGER_SUCCESS) {
        WIFI_LOGI("StopNetEapObserver unregister success");
        return true;
    }
    WIFI_LOGI("StopNetEapObserver failed, ret=%{public}d", ret);
    return false;
}

void NetEapObserver::OnWifiStateOpen(int state)
{
    if (state == static_cast<int>(OperateResState::OPEN_WIFI_SUCCEED)) {
        ReRegisterCustomEapCallback();
    }
}

void NetEapObserver::ReRegisterCustomEapCallback()
{
    WIFI_LOGI("%{public}s, enter", __func__);
    if (netEapCallback_ == nullptr) {
        WIFI_LOGE("%{public}s, netEapCallback_ is nullptr", __func__);
        return;
    }
    auto callback = netEapCallback_->GetRegisterCustomEapCallback();
    if (callback == nullptr) {
        WIFI_LOGE("%{public}s, callback is nullptr", __func__);
        return;
    }
    callback(netEapCallback_->regCmd_);
}

bool NetEapObserver::NotifyWpaEapInterceptInfo(const WpaEapData &wpaEapData)
{
    sptr<NetManagerStandard::EapData> notifyEapData = (std::make_unique<NetManagerStandard::EapData>()).release();
    notifyEapData->eapCode = wpaEapData.code;
    notifyEapData->eapType = wpaEapData.type;
    notifyEapData->msgId = wpaEapData.msgId;
    notifyEapData->bufferLen = wpaEapData.bufferLen;
    notifyEapData->eapBuffer = std::move(wpaEapData.eapBuffer);
    int32_t ret = DelayedSingleton<NetManagerStandard::EthernetClient>::GetInstance()->NotifyWpaEapInterceptInfo(
        NetManagerStandard::NetType::WLAN0, notifyEapData);
    if (ret != NetManagerStandard::NETMANAGER_SUCCESS) {
        WIFI_LOGE("%{public}s fail, ret:%{public}d", __func__, ret);
        return false;
    }
    return true;
}

NetEapCallback::NetEapCallback()
{
}

NetEapCallback::~NetEapCallback()
{
}

bool NetEapCallback::SetRegisterCustomEapCallback(const std::function<void(const std::string &regCmd)> &callback)
{
    if (callback == nullptr) {
        WIFI_LOGE("%{public}s, callback is nullptr", __func__);
        return false;
    }
    regCallback_ = callback;
    return true;
}

std::function<void(const std::string &)> NetEapCallback::GetRegisterCustomEapCallback()
{
    return regCallback_;
}

bool NetEapCallback::SetReplyCustomEapDataCallback(const std::function<void(int, const std::string&)> &callback)
{
    if (callback == nullptr) {
        WIFI_LOGE("%{public}s, callback is nullptr", __func__);
        return false;
    }
    replyCallback_ = callback;
    return true;
}

int32_t NetEapCallback::OnRegisterCustomEapCallback(const std::string &regCmd)
{
    if (regCmd_ == regCmd) {
        WIFI_LOGW("%{public}s regCmd is registered, %{public}s", __func__, regCmd.c_str());
        return WIFI_OPT_SUCCESS;
    }
    regCmd_ = regCmd;
    if (regCallback_ == nullptr) {
        WIFI_LOGE("%{public}s regCallback_ is nullptr", __func__);
        return WIFI_OPT_FAILED;
    }
    regCallback_(regCmd_);
    return WIFI_OPT_SUCCESS;
}

int32_t NetEapCallback::OnReplyCustomEapDataEvent(int result, const sptr<NetManagerStandard::EapData> &eapData)
{
    if (eapData == nullptr) {
        WIFI_LOGE("%{public}s, eapData is nullptr", __func__);
        return WIFI_OPT_FAILED;
    }
    if (replyCallback_ == nullptr) {
        WIFI_LOGE("%{public}s, replyCallback_ is nullptr, %{public}s", __func__, eapData->PrintLogInfo().c_str());
        return WIFI_OPT_FAILED;
    }
    std::string encodeEapData = EncodeBase64(eapData->eapBuffer);
    if (encodeEapData.empty()) {
        WIFI_LOGE("%{public}s, encodeEapData is empty, %{public}s", __func__, eapData->PrintLogInfo().c_str());
        return WIFI_OPT_FAILED;
    }
    std::ostringstream oss;
    oss << eapData->msgId << ":";
    oss << eapData->bufferLen << ":";
    oss << encodeEapData;
    replyCallback_(result, oss.str());
    return WIFI_OPT_SUCCESS;
}

}
}