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

#include "external_wifi_filter_builder_manager.h"
#include "wifi_logger.h"
#include "wifi_filter_impl.h"


namespace OHOS::Wifi {
DEFINE_WIFILOG_LABEL("WifiFilterBuilderManager")

ExternalWifiFilterBuildManager &ExternalWifiFilterBuildManager::GetInstance()
{
    static ExternalWifiFilterBuildManager gNetworkSelectorFilterBuilderManager;
    return gNetworkSelectorFilterBuilderManager;
}

void ExternalWifiFilterBuildManager::RegisterFilterBuilder(const FilterTag &filterTag,
                                                           const std::string &filterName,
                                                           const FilterBuilder &filterBuilder)
{
    if (!filterBuilder) {
        WIFI_LOGE("the filterBuilder for filterTag: %{public}d, filterName: %{public}s is empty",
                  static_cast<int>(filterTag),
                  filterName.c_str());
        return;
    }
    std::lock_guard<std::mutex> lock(mutex);
    WIFI_LOGI("RegisterFilterBuilder for filterTag: %{public}d, filterName: %{public}s",
              static_cast<int>(filterTag),
              filterName.c_str());
    filterBuilders.insert_or_assign({filterTag, filterName}, filterBuilder);
}

void ExternalWifiFilterBuildManager::DeregisterFilterBuilder(const FilterTag &filterTag, const std::string &filterName)
{
    std::lock_guard<std::mutex> lock(mutex);
    WIFI_LOGI("DeregisterFilterBuilder for filterTag: %{public}d, filterName: %{public}s",
              static_cast<int>(filterTag),
              filterName.c_str());
    filterBuilders.erase({filterTag, filterName});
}

void ExternalWifiFilterBuildManager::BuildFilter(const FilterTag &filterTag,
    NetworkSelection::CompositeWifiFilter &compositeFilter)
{
    std::lock_guard<std::mutex> lock(mutex);
    for (const auto &filterBuilderPair : filterBuilders) {
        /* find the builder which match the filterTag  */
        if (filterBuilderPair.first.first != filterTag) {
            continue;
        }
        filterBuilderPair.second.operator()(compositeFilter);
    }
}
}
