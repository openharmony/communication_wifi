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

#include "network_selector_filter.h"

namespace OHOS {
namespace Wifi {
bool IWifiFilter::DoFilter(NetworkCandidate &networkCandidate)
{
    bool filterResult = Filter(networkCandidate);
    AfterFilter(networkCandidate, filterResult);
    return filterResult;
}

void IWifiFilter::AfterFilter(NetworkCandidate &networkCandidate,
                              bool filterResult) {}

SimpleWifiFilter::SimpleWifiFilter(const std::string &networkSelectorFilterName)
    : IWifiFilter(), filterName(networkSelectorFilterName) {}

void SimpleWifiFilter::AfterFilter(NetworkCandidate &networkCandidate, bool filterResult)
{
    if (!filterResult) {
        networkCandidate.filteredMsg.emplace_back(filterName);
    }
}

std::string SimpleWifiFilter::GetFilterMsg()
{
    return filterName;
}

WifiFunctionFilter::WifiFunctionFilter(const std::function<bool(NetworkCandidate &)> &filter,
                                       const std::string &networkSelectorFilterName,
                                       bool reverse)
    : SimpleWifiFilter(networkSelectorFilterName), filterFunction(filter), iSReverse(reverse) {}

bool WifiFunctionFilter::Filter(NetworkCandidate &networkCandidate)
{
    return iSReverse != filterFunction.operator()(networkCandidate);
}

void CompositeWifiFilter::AddFilter(const std::shared_ptr<IWifiFilter> &filter)
{
    if (filter) {
        filters.emplace_back(filter);
    }
}

bool AndWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    return std::all_of(filters.begin(), filters.end(), [&networkCandidate](auto filter) {
        return filter->DoFilter(networkCandidate);
    });
}

std::string AndWifiFilter::GetFilterMsg()
{
    std::stringstream filterMsg;
    filterMsg << "(";
    for (auto i = 0; i < filters.size(); i++) {
        filterMsg << filters.at(i)->GetFilterMsg();
        if (i < filters.size() - 1) {
            filterMsg << "&&";
        }
    }
    filterMsg << ")";
    return filterMsg.str();
}

bool OrWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    return std::any_of(filters.begin(), filters.end(), [&networkCandidate](auto filter) {
        return filter->DoFilter(networkCandidate);
    });
}

std::string OrWifiFilter::GetFilterMsg()
{
    std::stringstream filterMsg;
    filterMsg << "(";
    for (auto i = 0; i < filters.size(); i++) {
        filterMsg << filters.at(i)->GetFilterMsg();
        if (i < filters.size() - 1) {
            filterMsg << "||";
        }
    }
    filterMsg << ")";
    return filterMsg.str();
}
}
}