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

#ifndef OHOS_WIFI_NETWORK_SELECTOR_FILTER_H_
#define OHOS_WIFI_NETWORK_SELECTOR_FILTER_H_

#include <memory>
#include "network_selection_msg.h"

namespace OHOS {
namespace Wifi {
class IWifiFilter {
public:
    virtual ~IWifiFilter() = default;

    /**
     * filter the candidate network
     * @param networkCandidate candidate network.
     * @return true if the candidate network satisfy the condition
     */
    virtual bool DoFilter(NetworkCandidate &networkCandidate) final;
    virtual std::string GetFilterMsg() = 0;
protected:

    /**
     * filter the candidate network
     * @param networkCandidate candidate network.
     * @return true if the candidate network satisfy the condition
     */
    virtual bool Filter(NetworkCandidate &networkCandidate) = 0;

    /**
     * deal with the candidate network after filter
     * @param networkCandidate candidate network.
     * @param filterResult  if the candidate network satisfy the condition
     */
    virtual void AfterFilter(NetworkCandidate &networkCandidate, bool filterResult);
};

class SimpleWifiFilter : public IWifiFilter {
public:
    explicit SimpleWifiFilter(const std::string &networkSelectorFilterName);
    std::string GetFilterMsg() final;
protected:
    void AfterFilter(NetworkCandidate &networkCandidate, bool filterResult) override;
    std::string filterName;
};

class WifiFunctionFilter : public SimpleWifiFilter {
public:

    /**
     *
     * @param filter the point to filterFunction
     * @param networkSelectorFilterName the filterName
     * @param reverse for default it should be filtered when the function return true, And it can be modified;
     */
    WifiFunctionFilter(const std::function<bool(NetworkCandidate &)> &filter,
                       const std::string &networkSelectorFilterName,
                       bool reverse = false);
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
    std::function<bool(NetworkCandidate &)> filterFunction;
    bool iSReverse;
};

class CompositeWifiFilter : public IWifiFilter {
public:
    CompositeWifiFilter() = default;
    /**
     *  Add Filter for composite network selector filter
     * @param filter filter
     */
    virtual void AddFilter(const std::shared_ptr<IWifiFilter> &filter);
protected:
    std::vector<std::shared_ptr<IWifiFilter>> filters;
};

class AndWifiFilter : public CompositeWifiFilter {
public:
    AndWifiFilter() = default;
    bool Filter(NetworkCandidate &networkCandidate) override;
    std::string GetFilterMsg() override;
};

class OrWifiFilter : public CompositeWifiFilter {
public:
    OrWifiFilter() = default;
    bool Filter(NetworkCandidate &networkCandidate) override;
    std::string GetFilterMsg() override;
};
}
}
#endif
