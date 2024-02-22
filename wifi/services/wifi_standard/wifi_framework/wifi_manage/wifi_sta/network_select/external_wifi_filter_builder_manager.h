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

#ifndef OHOS_WIFI_EXTERNAL_NETWORK_FILTER_BUILDER_MANAGER_H_
#define OHOS_WIFI_EXTERNAL_NETWORK_FILTER_BUILDER_MANAGER_H_

#include <mutex>
#include "network_selection.h"

namespace OHOS::Wifi {
class ExternalWifiFilterBuildManager {
public:
    static ExternalWifiFilterBuildManager &GetInstance();

    ExternalWifiFilterBuildManager(const ExternalWifiFilterBuildManager &) = delete;

    const ExternalWifiFilterBuildManager &operator=(const ExternalWifiFilterBuildManager &) = delete;

    /**
     * Register the filter builder function
     *
     * @param filterTag filterTag which define where the filter should be inserted.
     * @param filterName the filter name.
     * @param filterBuilder filterBuilder function.
     */
    void RegisterFilterBuilder(const FilterTag &filterTag, const std::string &filterName,
                               const FilterBuilder &filterBuilder);
    /**
     * Deregister the filter builder function
     *
     * @param filterTag filterTag which define where the filter should be inserted.
     * @param filterName the filter name.
     */
    void DeregisterFilterBuilder(const FilterTag &filterTag, const std::string &filterName);

    /**
     * build the compositeFilter
     *
     * @param filterTag filterTag which define where the compositeFilter should be inserted.
     * @param compositeFilter the target Filter to build.
     */
    void BuildFilter(const FilterTag &filterTag, NetworkSelection::CompositeWifiFilter &compositeFilter);
private:
    ExternalWifiFilterBuildManager() = default;

    ~ExternalWifiFilterBuildManager() = default;

    std::map<std::pair<FilterTag, std::string>, FilterBuilder> filterBuilders;
    std::mutex mutex;
};
}

#endif