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

#ifndef OHOS_WIFI_EXTERNAL_NETWORK_COMMON_BUILDER_MANAGER_H_
#define OHOS_WIFI_EXTERNAL_NETWORK_COMMON_BUILDER_MANAGER_H_

#include <mutex>
#include "network_selection.h"

namespace OHOS::Wifi {
class ExternalWifiCommonBuildManager {
public:
    static ExternalWifiCommonBuildManager &GetInstance();

    ExternalWifiCommonBuildManager(const ExternalWifiCommonBuildManager &) = delete;

    const ExternalWifiCommonBuildManager &operator=(const ExternalWifiCommonBuildManager &) = delete;

    /**
     * Register the common builder function
     *
     * @param TagType scoreTag which define where the score or filter should be inserted.
     * @param tagName the score or filter name.
     * @param CommonBuilder CommonBuilder function.
     */
    void RegisterCommonBuilder(const TagType &tagType, const std::string &tagName,
                               const CommonBuilder &commonBuilder);
    /**
     * Deregister the common builder function
     *
     * @param TagType TagType which define where the score or filter should be inserted.
     * @param tagName the score or filte name.
     */
    void DeregisterCommonBuilder(const TagType &tagType, const std::string &tagName);

    /**
     * build the compositeScore
     *
     * @param scoreTag scoreTag which define where the compositeScore should be inserted.
     * @param compositeScore the target score to build.
     */
    void BuildScore(const TagType &scoreTag, NetworkSelection::CompositeWifiScorer &compositeScore);

    /**
     * build the compositeFilter
     *
     * @param filterTag filterTag which define where the compositeFilter should be inserted.
     * @param compositeFilter the target Filter to build.
     */
    void BuildFilter(const TagType &filterTag, NetworkSelection::CompositeWifiFilter &compositeFilter);

private:
    ExternalWifiCommonBuildManager() = default;

    ~ExternalWifiCommonBuildManager() = default;

    std::map<std::pair<TagType, std::string>, CommonBuilder> commonBuilders;
    std::mutex mutex;
};
}

#endif