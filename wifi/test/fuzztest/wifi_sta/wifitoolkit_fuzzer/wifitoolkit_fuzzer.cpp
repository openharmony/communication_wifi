/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "wifitoolkit_fuzzer.h"
#include "wifi_fuzz_common_func.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "securec.h"
#include "define.h"
#include "wifi_log.h"
#include "wifi_app_parser.h"
#include "wifi_settings.h"
#include "network_parser.h"
#include "wifi_internal_msg.h"
#include "wifi_errcode.h"
#include "xml_parser.h"
#include "softap_parser.h"
#include "wifi_randommac_helper.h"
#include "wifi_asset_manager.h"
#include "wifi_encryption_util.h"
#include <mutex>
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Wifi {
constexpr int U32_AT_SIZE_ZERO = 4;
constexpr int WIFI_MAX_SSID_LEN = 16;
constexpr int TWO = 2;
constexpr int FORTYTHREE = 43;
constexpr int HUNDRED = 100;
static bool g_isInsted = false;
FuzzedDataProvider *FDP = nullptr;
static const int32_t NUM_BYTES = 1;


class MockXmlParser : public XmlParser {
public:
    bool ParseInternal(xmlNodePtr node)
    {
        return false;
    }
};
static xmlNodePtr root_node;
static std::unique_ptr<NetworkXmlParser> m_networkXmlParser = nullptr;
static std::unique_ptr<AppParser> m_appXmlParser = nullptr;
static std::unique_ptr<MockXmlParser> m_xmlParser = nullptr;
static std::unique_ptr<SoftapXmlParser> m_softapXmlParser = nullptr;
static std::unique_ptr<WifiRandomMacHelper> m_WifiRandomMacHelper = nullptr;
static std::unique_ptr<WifiAssetManager> m_WifiAssetManager = nullptr;

void MyExit()
{
    m_networkXmlParser.reset();
    m_appXmlParser.reset();
    m_xmlParser.reset();
    m_softapXmlParser.reset();
    sleep(3);
    printf("exiting\n");
}

void InitAppParserTest()
{
    root_node = xmlNewNode(NULL, BAD_CAST("MonitorAPP"));
    xmlNodePtr gameAppNode = xmlNewTextChild(root_node, NULL, BAD_CAST("GameInfo"), NULL);
    xmlNewProp(gameAppNode, BAD_CAST("gameName"), BAD_CAST "gameApp");
    xmlNodePtr whileListAppNode = xmlNewTextChild(root_node, NULL, BAD_CAST("AppWhiteList"), NULL);
    xmlNewProp(whileListAppNode, BAD_CAST("packageName"), BAD_CAST "whiteListApp");
    xmlNodePtr blackListAppNode = xmlNewTextChild(root_node, NULL, BAD_CAST("AppBlackList"), NULL);
    xmlNewProp(blackListAppNode, BAD_CAST("packageName"), BAD_CAST "blackListApp");
    xmlNodePtr chariotAppNode = xmlNewTextChild(root_node, NULL, BAD_CAST("ChariotApp"), NULL);
    xmlNewProp(chariotAppNode, BAD_CAST("packageName"), BAD_CAST "chariotApp");
}

void InitParam()
{
    if (!g_isInsted) {
        m_networkXmlParser = std::make_unique<NetworkXmlParser>();
        m_appXmlParser = std::make_unique<AppParser>();
        m_xmlParser = std::make_unique<MockXmlParser>();
        m_softapXmlParser = std::make_unique<SoftapXmlParser>();
        InitAppParserTest();
        if (m_networkXmlParser == nullptr) {
            return;
        }
        atexit(MyExit);
        g_isInsted = true;
    }
    return;
}

void NetworkXmlParserTest(const uint8_t* data, size_t size)
{
    WifiDeviceConfig config;
    config.ssid = std::string(reinterpret_cast<const char*>(data), size);
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);

    m_networkXmlParser->GetIpConfig(root_node);
    m_networkXmlParser->GetConfigNameAsInt(root_node);
    m_networkXmlParser->GotoNetworkList(root_node);
    m_networkXmlParser->GetNodeNameAsInt(root_node);
    m_networkXmlParser->ParseIpConfig(root_node);
    m_networkXmlParser->GetProxyMethod(root_node);
    m_networkXmlParser->ParseProxyConfig(root_node);
    m_networkXmlParser->HasWepKeys(config);
    m_networkXmlParser->GetKeyMgmt(root_node, config);
    m_networkXmlParser->GetRandMacSetting(nullptr);
    m_networkXmlParser->ParseWifiConfig(root_node);
    m_networkXmlParser->ParseNetworkStatus(root_node, config);
    m_networkXmlParser->ParseWepKeys(root_node, config);
    m_networkXmlParser->ParseStatus(root_node, config);
    m_networkXmlParser->ParseNetwork(root_node);
    m_networkXmlParser->IsWifiConfigValid(config);

    m_networkXmlParser->ParseNetworkList(root_node);
    m_networkXmlParser->GetParseType(root_node);
    m_networkXmlParser->ParseInternal(root_node);
    m_networkXmlParser->EnableNetworks();
}

void AppXmlParserTest(const uint8_t* data, size_t size)
{
    std::string conditionName = std::string(reinterpret_cast<const char*>(data), size);
    char *string = nullptr;
    if (memcpy_s(string, WIFI_MAX_SSID_LEN, data, WIFI_MAX_SSID_LEN - 1) != EOK) {
        return;
    }
    int gameRtt = *reinterpret_cast<const int*>(data);
    m_appXmlParser->Init();
    m_appXmlParser->IsLowLatencyApp(conditionName);
    m_appXmlParser->IsWhiteListApp(conditionName);
    m_appXmlParser->IsBlackListApp(conditionName);
    m_appXmlParser->IsMultiLinkApp(conditionName);
    m_appXmlParser->IsChariotApp(conditionName);
    m_appXmlParser->IsHighTempLimitSpeedApp(conditionName);
    m_appXmlParser->IsKeyForegroundApp(conditionName);
    m_appXmlParser->IsKeyBackgroundLimitApp(conditionName);
    m_appXmlParser->IsLiveStreamApp(conditionName);
    m_appXmlParser->IsGameBackgroundLimitApp(conditionName);
    m_appXmlParser->IsOverGameRtt(conditionName, gameRtt);
    m_appXmlParser->GetAsyncLimitSpeedDelayTime();
    m_appXmlParser->appParserInner_->InitAppParser(string);
    m_appXmlParser->appParserInner_->ParseInternal(root_node);
    m_appXmlParser->appParserInner_->ParseAppList(root_node);
    m_appXmlParser->appParserInner_->ParseNetworkControlAppList(root_node);
    m_appXmlParser->appParserInner_->ParseLowLatencyAppInfo(root_node);
    m_appXmlParser->appParserInner_->ParseWhiteAppInfo(root_node);
    m_appXmlParser->appParserInner_->ParseBlackAppInfo(root_node);
    m_appXmlParser->appParserInner_->ParseMultiLinkAppInfo(root_node);
    m_appXmlParser->appParserInner_->ParseChariotAppInfo(root_node);
    m_appXmlParser->appParserInner_->ParseHighTempLimitSpeedAppInfo(root_node);
    m_appXmlParser->appParserInner_->ParseKeyForegroundListAppInfo(root_node);
    m_appXmlParser->appParserInner_->ParseKeyBackgroundLimitListAppInfo(root_node);
    m_appXmlParser->appParserInner_->ParseLiveStreamAppInfo(root_node);
    m_appXmlParser->appParserInner_->ParseGameBackgroundLimitListAppInfo(root_node);
    m_appXmlParser->appParserInner_->ParseAsyncLimitSpeedDelayTime(root_node);
    m_appXmlParser->appParserInner_->GetAppTypeAsInt(root_node);
    m_appXmlParser->appParserInner_->GetLocalFileVersion(root_node);
    m_xmlParser->LoadConfiguration(string);
    m_xmlParser->LoadConfigurationMemory(string);
    ConvertStringToBool(string);
}

void AppParserTest(const uint8_t* data, size_t size)
{
    m_xmlParser->Parse();
    m_xmlParser->GetNameValue(root_node);
    m_xmlParser->GetNodeValue(root_node);
    m_xmlParser->GetStringValue(root_node);
    m_xmlParser->GetStringArrValue(root_node);
    m_xmlParser->GetByteArrValue(root_node);
    m_xmlParser->GetStringMapValue(root_node);
    m_xmlParser->IsDocValid(root_node);
}

void SoftapParserTest(const uint8_t* data, size_t size)
{
    m_softapXmlParser->ParseInternal(root_node);
    m_softapXmlParser->GotoSoftApNode(root_node);
    m_softapXmlParser->ParseSoftap(root_node);
    m_softapXmlParser->GetConfigNameAsInt(root_node);
    m_softapXmlParser->GetBandInfo(root_node);
    m_softapXmlParser->TransBandinfo(root_node);
    m_softapXmlParser->GetSoftapConfigs();
}

void WifiRandomMacHelperTest(const uint8_t* data, size_t size)
{
    int index = 0;
    unsigned long long addr1 = static_cast<unsigned long long>(data[index++]);
    unsigned long long random = static_cast<unsigned long long>(data[index++]);
    std::string content = std::string(reinterpret_cast<const char*>(data), size);
    std::string randomMacAddr = std::string(reinterpret_cast<const char*>(data), size);
    std::vector<uint8_t> outPlant;
    std::vector<uint8_t> byte;
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> addr;
    bool value = (static_cast<int>(data[0]) % TWO) ? true : false;
    #ifdef SUPPORT_LOCAL_RANDOM_MAC
    m_WifiRandomMacHelper->CalculateRandomMacForWifiDeviceConfig(content, randomMacAddr);
    #endif
    m_WifiRandomMacHelper->GetRandom();
    m_WifiRandomMacHelper->GenerateRandomMacAddress(randomMacAddr);
    m_WifiRandomMacHelper->LongLongToBytes(value, outPlant);
    m_WifiRandomMacHelper->BytesToLonglong(byte);
    m_WifiRandomMacHelper->BytesArrayToString(bytes);
    m_WifiRandomMacHelper->StringAddrFromLongAddr(addr1, randomMacAddr);
    m_WifiRandomMacHelper->LongAddrFromByteAddr(addr);
    m_WifiRandomMacHelper->GenerateRandomMacAddressByLong(random, randomMacAddr);
}

void AssetManagerTest()
{
    WifiDeviceConfig config;
    int32_t randomInt = FDP->ConsumeIntegral<int32_t>();
    OperateResState state = static_cast<OperateResState>(randomInt % FORTYTHREE);
    WifiLinkedInfo info;
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    if (tmpInt <= 0 || tmpInt > HUNDRED) {
        return;
    }
    std::vector<WifiDeviceConfig>wifiDeviceConfigs;
    std::vector<WifiDeviceConfig> newWifiDeviceConfigs;
    bool flagSync = FDP->ConsumeIntegral<bool>();
    bool firstSync = FDP->ConsumeIntegral<bool>();
    m_WifiAssetManager->WifiAssetQuery(tmpInt);
    m_WifiAssetManager->WifiAssetUpdate(config, tmpInt);
    m_WifiAssetManager->WifiAssetAddPack(wifiDeviceConfigs, tmpInt, flagSync, firstSync);
    m_WifiAssetManager->WifiAssetUpdatePack(wifiDeviceConfigs, tmpInt);
    m_WifiAssetManager->WifiAssetRemovePack(wifiDeviceConfigs, tmpInt, flagSync);
    m_WifiAssetManager->WifiAssetRemoveAll(tmpInt, flagSync);
    m_WifiAssetManager->IsWifiConfigUpdated(newWifiDeviceConfigs, config);
    m_WifiAssetManager->WifiAssetRemoveAll(tmpInt, flagSync);
    m_WifiAssetManager->IsWifiConfigUpdated(newWifiDeviceConfigs, config);
    m_WifiAssetManager->DealStaConnChanged(state, info, tmpInt);
}

void WifiencryptionutilTest()
{
    WifiEncryptionInfo wifiEncryptionInfo;
    EncryptedData encryptedData;
    std::string decryptedData = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string key = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string inputString = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string keyName = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string data = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::vector<uint8_t> outPlant;
    SetUpHks();
    WifiDecryption(wifiEncryptionInfo, encryptedData, decryptedData);
    ImportKey(wifiEncryptionInfo, key);
    DeleteKey(wifiEncryptionInfo);
    WifiLoopEncrypt(wifiEncryptionInfo, inputString, encryptedData);
    WifiLoopDecrypt(wifiEncryptionInfo, encryptedData, decryptedData);
    WifiGenerateMacRandomizationSecret(keyName, data, outPlant);
}


/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    OHOS::Wifi::FDP = &fdp;
    OHOS::Wifi::InitParam();
    OHOS::Wifi::NetworkXmlParserTest(data, size);
    OHOS::Wifi::AppXmlParserTest(data, size);
    OHOS::Wifi::AppParserTest(data, size);
    OHOS::Wifi::SoftapParserTest(data, size);
    OHOS::Wifi::WifiRandomMacHelperTest(data, size);
    OHOS::Wifi::WifiencryptionutilTest();
    OHOS::Wifi::AssetManagerTest();
    return 0;
}
}
}
