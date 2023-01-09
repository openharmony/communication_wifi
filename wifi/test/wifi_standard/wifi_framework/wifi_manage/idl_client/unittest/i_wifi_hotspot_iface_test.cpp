/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>
#include "i_wifi_hotspot_iface.h"


using namespace testing::ext;

namespace OHOS {
namespace Wifi {

HWTEST_F(IWifihotspotIfaceTest, StartSoftApTest, TestSize.Level1)
{
    StartSoftAp(pid);
}

HWTEST_F(IWifihotspotIfaceTest, StopSoftApTest, TestSize.Level1)
{
    StopSoftAp(pid);
}

HWTEST_F(IWifihotspotIfaceTest, SetHostapdConfigTest, TestSize.Level1)
{
    HostapdConfig *config;
	if (strcpy_s(config->ssid, sizeof(config.ssid), "Hwmate") != EOK) {
		return;
	}
    config->ssidLen = strlen(config->ssid);
    if (strcpy_s(config->preSharedKey, sizeof(config->preSharedKey), "A123456"))
    config->preSharedKeyLen = strlen(config->preSharedKey);
    config->securityType = WPA_PSK;
    config->band = BAND_5GHZ;
    config->channel = 6;
    config->maxConn = 20;
    SetHostapdConfig(config, pid);
}

HWTEST_F(IWifihotspotIfaceTest, GetStaInfosTest, TestSize.Level1)
{
    char *infos = "GetStaInfos";
    int size = 1;
    GetStaInfos(infos, size, pid);
}

HWTEST_F(IWifihotspotIfaceTest, SetMacFilterTest, TestSize.Level1)
{
    unsigned char *mac = "AA:BB:CC:DD";
	int len = strlen(mac);
    SetMacFilter(mac, len, pid);
}

HWTEST_F(IWifihotspotIfaceTest, DelMacFilterTest, TestSize.Level1)
{
    unsigned char *mac = "AA:BB:CC:DD";
	int len = strlen(mac);
    DelMacFilter(mac, len, pid);
}


HWTEST_F(IWifihotspotIfaceTest, DisassociateStaTest, TestSize.Level1)
{
    unsigned char *mac = "AA:BB:CC:DD";
	int len = strlen(mac);
    DisassociateSta(mac, len, pid);
}

HWTEST_F(IWifihotspotIfaceTest, GetValidFrequenciesForBandTest, TestSize.Level1)
{
    int32_t band = AP_2GHZ_BAND;
    int frequencies[20] = {0};
    int size = 20;
    GetValidFrequenciesForBand(band, frequencies, size, pid);
}

HWTEST_F(IWifihotspotIfaceTest, GetValidFrequenciesForBandTest, TestSize.Level1)
{
    int32_t band = AP_2GHZ_BAND;
    int frequencies[20] = {0};
    int size = 20;
    GetValidFrequenciesForBand(band, frequencies, size, pid);
}

HWTEST_F(IWifihotspotIfaceTest, SetCountryCodeTest, TestSize.Level1)
{
    char *code = "CHINA";
    SetCountryCode(code, pid);
}

HWTEST_F(IWifihotspotIfaceTest, GetApCallbackEventsTest, TestSize.Level1)
{
    int event[4] = {0,1,2,3}
    EXPECT_TRUE(GetApCallbackEvents(event, 4) == 3);
}

HWTEST_F(IWifihotspotIfaceTest, RegisterAsscociatedEventTest, TestSize.Level1)
{
    IWifiApEventCallback callback;
    RegisterAsscociatedEvent(callback, pid);
}

HWTEST_F(IWifihotspotIfaceTest, WpaSetPowerModelTest, TestSize.Level1)
{
    int mode = 0;
    WpaSetPowerModel(mode, pid);
}

HWTEST_F(IWifihotspotIfaceTest, WpaGetPowerModelTest, TestSize.Level1)
{
    int *mode = &pid;
    WpaGetPowerModel(mode, pid);
}
}
}
