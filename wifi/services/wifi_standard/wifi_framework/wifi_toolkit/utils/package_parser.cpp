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

#include "package_parser.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("PackageXmlParser");

PackageXmlParser::~PackageXmlParser()
{}

bool PackageXmlParser::ParseInternal(xmlNodePtr node)
{
    if (node == nullptr) {
        WIFI_LOGE("ParseInternal node null");
        return false;
    }
    if (xmlStrcmp(node->name, BAD_CAST(TAG_HEADER)) != 0) {
        WIFI_LOGE("node name=%{public}s not equal WifiPackages", node->name);
        return false;
    }
    mScanControlFilterMap.clear();
    mCandidateFilterList.clear();
    mCorePackageMap.clear();
    mAclAuthList.clear();
    mScanLimitPackage_.clear();
    mLandscapeSwitchLimitList_.clear();
    for (xmlNodePtr subNode = node->children; subNode != nullptr; subNode = subNode->next) {
        std::string tagName = GetNodeValue(subNode);
        if (tagName == TAG_SCAN_CONTROL) {
            GetPackageMap(subNode, mScanControlFilterMap);
        } else if (tagName == TAG_CANDIDATE_FILTER) {
            GetPackageList(subNode, mCandidateFilterList);
        } else if (tagName == TAG_CORE_PACKAGEINFO) {
            GetPackageMap(subNode, mCorePackageMap);
        } else if (tagName == TAG_ACL_AUTH) {
            GetPackageList(subNode, mAclAuthList);
        } else if (tagName == TAG_SCAN_LIMIT) {
            GetPackageList(subNode, mScanLimitPackage_);
        } else if (tagName == TAG_LANDSCAPE_SWITCH_LIMIT) {
            GetPackageList(subNode, mLandscapeSwitchLimitList_);
        } else {
            WIFI_LOGI("unknow package tag.");
        }
    }
    return true;
}

void PackageXmlParser::GetPackageMap(xmlNodePtr &innode, std::map<std::string, std::vector<PackageInfo>> &result)
{
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        std::string tagName = GetNodeValue(node);
        std::vector<PackageInfo> packageNodeList;
        GetPackageList(node, packageNodeList);
        result.insert_or_assign(tagName, packageNodeList);
    }
    WIFI_LOGI("%{public}s out,result size:%{public}d!", __FUNCTION__, (int)result.size());
}

void PackageXmlParser::GetPackageList(xmlNodePtr &innode, std::vector<PackageInfo> &packageNodeList)
{
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        PackageInfo info;
        ParseFinalNode(node, info);
        if (!info.name.empty()) {
            packageNodeList.emplace_back(info);
        }
    }
}

void PackageXmlParser::ParseFinalNode(xmlNodePtr &innode, PackageInfo &info)
{
    xmlChar* name = xmlGetProp(innode, BAD_CAST(PARAM_NAME));
    if (name != nullptr) {
        info.name = std::string(reinterpret_cast<char *>(name));
        xmlFree(name);
    }
    xmlChar* appid = xmlGetProp(innode, BAD_CAST(PARAM_APPID));
    if (appid != nullptr) {
        info.appid = std::string(reinterpret_cast<char *>(appid));
        xmlFree(appid);
    }
}

void PackageXmlParser::GetScanControlPackages(std::map<std::string, std::vector<PackageInfo>> &packageMap)
{
    packageMap = mScanControlFilterMap;
}

void PackageXmlParser::GetCandidateFilterPackages(std::vector<PackageInfo> &packageList)
{
    packageList = mCandidateFilterList;
}

void PackageXmlParser::GetCorePackages(std::map<std::string, std::vector<PackageInfo>> &packageMap)
{
    packageMap = mCorePackageMap;
}

void PackageXmlParser::GetAclAuthPackages(std::vector<PackageInfo> &packageList)
{
    packageList = mAclAuthList;
}

void PackageXmlParser::GetScanLimitPackages(std::vector<PackageInfo> &packageList)
{
    packageList = mScanLimitPackage_;
}
 
void PackageXmlParser::GetLandscapeSwitchLimitList(std::vector<PackageInfo> &packageList)
{
    packageList = mLandscapeSwitchLimitList_;
}
}
}