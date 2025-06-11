/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef PACKAGE_PARSER
#define PACKAGE_PARSER
#include "xml_parser.h"
#include "wifi_internal_msg.h"
#include <unordered_map>

constexpr auto TAG_HEADER = "WifiPackages";
constexpr auto TAG_SCAN_CONTROL = "ScanControlPackages";
constexpr auto TAG_CANDIDATE_FILTER = "CandidateFilterPackages";
constexpr auto TAG_CORE_PACKAGEINFO = "CorePackages";
constexpr auto TAG_ACL_AUTH = "AclAuthPackages";
constexpr auto TAG_SCAN_LIMIT = "ScanLimitPackages";
constexpr auto TAG_SWITCH_LIMIT = "SwitchLimitPackages";
constexpr auto PARAM_NAME = "name";
constexpr auto PARAM_APPID = "appid";

namespace OHOS {
namespace Wifi {

class PackageXmlParser : public XmlParser {
public:
    PackageXmlParser() = default;
    ~PackageXmlParser() override;
    void GetScanControlPackages(std::map<std::string, std::vector<PackageInfo>> &packageMap);
    void GetCandidateFilterPackages(std::vector<PackageInfo> &packageList);
    void GetCorePackages(std::map<std::string, std::vector<PackageInfo>> &packageMap);
    void GetAclAuthPackages(std::vector<PackageInfo> &packageList);
    void GetScanLimitPackages(std::vector<PackageInfo> &packageList);
    void GetSwitchLimitPackages(std::vector<PackageInfo> &packageList);

private:
    bool ParseInternal(xmlNodePtr node) override;
    void GetPackageMap(xmlNodePtr &innode, std::map<std::string, std::vector<PackageInfo>> &result);
    void GetPackageList(xmlNodePtr &innode, std::vector<PackageInfo> &packageNodeList);
    void ParseFinalNode(xmlNodePtr &innode, PackageInfo &info);

    std::map<std::string, std::vector<PackageInfo>> mScanControlFilterMap;
    std::vector<PackageInfo> mCandidateFilterList;
    std::map<std::string, std::vector<PackageInfo>> mCorePackageMap;
    std::vector<PackageInfo> mAclAuthList;
    std::vector<PackageInfo> mScanLimitPackage_;
    std::vector<PackageInfo> mSwitchLimitPackage_;
};
}
}
#endif