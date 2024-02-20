/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
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

#include "xml_parser.h"
#include "wifi_logger.h"
#include <vector>

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("XmlParser");

XmlParser::~XmlParser()
{
    Destroy();
}

void XmlParser::Destroy()
{
    if (mDoc_ != nullptr) {
        xmlFreeDoc(mDoc_);
        xmlCleanupParser();
        mDoc_ = nullptr;
    }
}

bool XmlParser::LoadConfiguration(const char *xmlPath)
{
    mDoc_ = xmlReadFile(xmlPath, nullptr, XML_PARSE_NOBLANKS);
    if (mDoc_ == nullptr) {
        WIFI_LOGE("LoadConfiguration fail");
        return false;
    }
    return true;
}

bool XmlParser::LoadConfigurationMemory(const char *xml)
{
    if (xml == nullptr) {
        WIFI_LOGE("LoadConfigurationMemory xml is nullptr");
        return false;
    }
    mDoc_ = xmlReadMemory(xml, strlen(xml), nullptr, nullptr, 0);
    if (mDoc_ == nullptr) {
        WIFI_LOGE("LoadConfigurationMemory fail");
        return false;
    }
    return true;
}

bool XmlParser::Parse()
{
    xmlNodePtr root = xmlDocGetRootElement(mDoc_);
    if (root == nullptr) {
        WIFI_LOGE("Parse root null");
        return false;
    }
    return ParseInternal(root);
}

std::string XmlParser::GetNameValue(xmlNodePtr node)
{
    if (node == nullptr || GetNodeValue(node).empty()) {
        return "";
    }
    xmlChar *value = xmlGetProp(node, BAD_CAST"name");
    if (value != nullptr) {
        return std::string(reinterpret_cast<char *>(value));
    } else {
        return "";
    }
}

std::string XmlParser::GetNodeValue(xmlNodePtr node)
{
    if (node == nullptr) {
        return "";
    }
    std::string nodeValue = std::string(reinterpret_cast<const char *>(node->name));
    if (nodeValue.empty() || nodeValue == "null") {
        return "";
    }
    return nodeValue;
}

std::string XmlParser::GetStringValue(xmlNodePtr node)
{
    if (node == nullptr) {
        return "";
    }
    xmlChar *value = xmlNodeGetContent(node);
    return std::string(reinterpret_cast<char *>(value));
}

std::vector<std::string> XmlParser::GetStringArrValue(xmlNodePtr innode)
{
    std::vector<std::string> stringArr{};
    if (innode == nullptr) {
        return stringArr;
    }
    xmlChar* numChar = xmlGetProp(innode, BAD_CAST"num");
    int num = std::stoi(std::string(reinterpret_cast<char *>(numChar)));
    if (num == 0) {
        return stringArr;
    }
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        if (xmlStrcmp(node->name, BAD_CAST"item") == 0) {
            xmlChar* value = xmlGetProp(node, BAD_CAST"value");
            stringArr.push_back(std::string(reinterpret_cast<char *>(value)));
        }
    }
    return stringArr;
}

std::vector<unsigned char> XmlParser::GetByteArrValue(xmlNodePtr node)
{
    std::vector<unsigned char> byteArr{};
    if (node == nullptr) {
        return byteArr;
    }
    xmlChar* numChar = xmlGetProp(node, BAD_CAST"num");
    int num = std::stoi(std::string(reinterpret_cast<char *>(numChar)));
    xmlChar *value = xmlNodeGetContent(node);
    std::string valueStr = std::string(reinterpret_cast<char *>(value));
    if (valueStr.length() != 2 * static_cast<size_t>(num)) { // byte length check
        return byteArr;
    }
    for (size_t i = 0; i < valueStr.length(); i += 2) { // trans string to byte
        std::string byteString = valueStr.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16)); // hex
        byteArr.push_back(byte);
    }
    return byteArr;
}

std::map<std::string, std::string> XmlParser::GetStringMapValue(xmlNodePtr innode)
{
    std::map<std::string, std::string> strMap{};
    if (innode == nullptr) {
        return strMap;
    }
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        std::string name;
        std::string value;
        if (xmlStrcmp(node->name, BAD_CAST"string") == 0) {
            xmlChar* xname = xmlGetProp(node, BAD_CAST"name");
            xmlChar* xvalue = xmlNodeGetContent(node);
            name = std::string(reinterpret_cast<char *>(xname));
            value = std::string(reinterpret_cast<char *>(xvalue));
            strMap[name] = value;
        }
    }
    return strMap;
}

bool XmlParser::IsDocValid(xmlNodePtr node)
{
    if (node == nullptr) {
        return false;
    }
    return (xmlStrcmp(node->name, BAD_CAST(XML_TAG_DOCUMENT_HEADER))  == 0);
}
}
}