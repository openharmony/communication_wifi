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

#ifndef XML_PARSER
#define XML_PARSER
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <iostream>
#include <map>

constexpr auto XML_TAG_DOCUMENT_HEADER = "WifiConfigStoreData";
inline bool ConvertStringToBool(const std::string str)
{
    if (str == "true") {
        return true;
    } else {
        return false;
    }
}
namespace OHOS {
namespace Wifi {
enum PrimType {
    INT,
    LONG,
    BOOLEAN,
};

class XmlParser {
public:
    virtual ~XmlParser();
    /**
     * @Description load a Configuration xml
     *
     * @param xmlPath - path of config xml
     * @return bool - true for succ false for fail
    */
    bool LoadConfiguration(const char *xmlPath);

    /**
     * @Description load xml in memory
     *
     * @param xml - memory data
     * @return bool - true for succ false for fail
    */
    bool LoadConfigurationMemory(const char *xml);

    /**
     * @Description parse Configuration xml
     *
     * @return bool - true for succ false for fail
    */
    bool Parse();

    /**
     * @Description get xml node name value
     *
     * @return std::string - node name value
    */
    std::string GetNameValue(xmlNodePtr node);

    /**
     * @Description get xml node value
     *
     * @param node - xmlNodePtr
     * @return std::string - node value
    */
    std::string GetNodeValue(xmlNodePtr node);

    /**
     * @Description get xml node string content
     *
     * @param node - xmlNodePtr
     * @return std::string - xml node string content
    */
    std::string GetStringValue(xmlNodePtr node);

    /**
     * @Description get xml node prime value eg:int bool
     *
     * @param node - xmlNodePtr
     * @param type - PrimType,eg INT,BOOL
     * @return T - prime value eg:int bool
    */
    template<typename T>
    T GetPrimValue(xmlNodePtr node, const PrimType type)
    {
        T primValue{};
        xmlChar* value = xmlGetProp(node, (const xmlChar*)"value");
        std::string valueString = std::string(reinterpret_cast<char *>(value));
        switch (type) {
            case PrimType::INT:
                primValue = std::stoi(valueString);
                break;
            case PrimType::LONG:
                primValue = std::stol(valueString);
                break;
            case PrimType::BOOLEAN:
                primValue = ConvertStringToBool(valueString);
                break;
            default: {
                break;
            }
        }
        return reinterpret_cast<T>(primValue);
    };

    /**
     * @Description get xml node string Array value
     *
     * @param innode - xmlNodePtr
     * @return std::vector<std::string> - prime value eg:int bool
    */
    std::vector<std::string> GetStringArrValue(xmlNodePtr innode);

    /**
     * @Description get xml node byte Array value
     *
     * @param innode - xmlNodePtr
     * @return std::vector<unsigned char> - byte Array value
    */
    std::vector<unsigned char> GetByteArrValue(xmlNodePtr node);

    /**
     * @Description get xml node string map value
     *
     * @param innode - xmlNodePtr
     * @return std::map<std::string, std::string> - node string map value
    */
    std::map<std::string, std::string> GetStringMapValue(xmlNodePtr innode);

    /**
     * @Description check doc is vaild
     *
     * @param node - xmlNodePtr
     * @return bool - true for valid false for unvalid
    */
    bool IsDocValid(xmlNodePtr node);

private:
    virtual bool ParseInternal(xmlNodePtr node) = 0;
    void Destroy();

private:
    xmlDoc *mDoc_ = nullptr;
};
}
}
#endif