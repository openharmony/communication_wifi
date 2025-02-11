/*

 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "external_wifi_common_builder_manager.h"
#include "wifi_logger.h"
#include "wifi_scorer_impl.h"


namespace OHOS::Wifi {
DEFINE_WIFILOG_LABEL("WifiCommonBuilderManager")

ExternalWifiCommonBuildManager &ExternalWifiCommonBuildManager::GetInstance()
{
    static ExternalWifiCommonBuildManager gNetworkSelectorCommonBuilderManager;
    return gNetworkSelectorCommonBuilderManager;
}

void ExternalWifiCommonBuildManager::RegisterCommonBuilder(const TagType &tagType, const std::string &tagName,
                                                           const CommonBuilder &commonBuilder)
{
    if (commonBuilder.IsEmpty()) {
        WIFI_LOGE("the scoreBuilder for tagType: %{public}d, tagName: %{public}s is empty",
                  static_cast<int>(tagType), tagName.c_str());
        return;
    }
    std::lock_guard<std::mutex> lock(mutex);
    WIFI_LOGI("RegisterCommonBuilder for tagType: %{public}d, tagName: %{public}s",
              static_cast<int>(tagType), tagName.c_str());
    if (commonBuilders.size() > REGISTERINFO_MAX_NUM) {
        WIFI_LOGW("%{public}s fail commonBuilders size is: %{public}d, over 1000",
            __FUNCTION__, static_cast<int>(commonBuilders.size()));
        return;
    }
    commonBuilders.insert_or_assign({tagType, tagName}, commonBuilder);
}

void ExternalWifiCommonBuildManager::DeregisterCommonBuilder(const TagType &tagType, const std::string &tagName)
{
    std::lock_guard<std::mutex> lock(mutex);
    WIFI_LOGI("DeregisterCommonBuilder for tagType: %{public}d, tagName: %{public}s",
              static_cast<int>(tagType), tagName.c_str());
    commonBuilders.erase({tagType, tagName});
}

void ExternalWifiCommonBuildManager::BuildScore(const TagType &scoreTag,
                                                NetworkSelection::CompositeWifiScorer &compositeScore)
{
    std::lock_guard<std::mutex> lock(mutex);
    for (const auto &commonBuilderPair : commonBuilders) {
        /* find the builder which match the filterTag  */
        if (commonBuilderPair.first.first != scoreTag) {
            continue;
        }
        commonBuilderPair.second.scoreBuilder.operator()(compositeScore);
    }
}

void ExternalWifiCommonBuildManager::BuildFilter(const TagType &filterTag,
    NetworkSelection::CompositeWifiFilter &compositeFilter)
{
    std::lock_guard<std::mutex> lock(mutex);
    for (const auto &commonBuilderPair : commonBuilders) {
        /* find the builder which match the filterTag  */
        if (commonBuilderPair.first.first != filterTag) {
            continue;
        }
        commonBuilderPair.second.filterBuilder.operator()(compositeFilter);
    }
}
}
