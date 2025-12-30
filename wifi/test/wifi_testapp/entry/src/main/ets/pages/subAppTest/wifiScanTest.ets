/**
 * Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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

import wifi from '@ohos.wifi';
import wifiManager from '@ohos.wifiManager';
import { AvailableWifi } from '../../component/availableWifi';
import { TitleBar } from '../../component/titleBar';
import { WifiModel } from '../../entryability/model/wifiModel';
import ConfigData from '../../utils/ConfigData';

const TAG = 'wifiTestApp [wifiScan]'

/**
 * wifi Found Test Page Of Wifi test
 */
@Entry
@Component
struct WifiScan {
  private wifiModel: WifiModel = new WifiModel()
  private testItem: string = "Wlan扫描";
  private isScanning: boolean = false;
  @State wifiList: Array<wifiManager.WifiScanInfo> = []
  @State isLinked: boolean = false
  @State isSwitchOn: boolean = false
  @State linkedInfo: wifiManager.WifiLinkedInfo = {
    ssid: '',
    bssid: '',
    networkId: 0,
    rssi: 0,
    band: 0,
    linkSpeed: 0,
    rxLinkSpeed: 0,
    maxSupportedTxLinkSpeed: 0,
    maxSupportedRxLinkSpeed: 0,
    frequency: 0,
    isHidden: false,
    isRestricted: false,
    chload: 0,
    snr: 0,
    macType: 0,
    macAddress: '',
    ipAddress: 0,
    suppState: wifiManager.SuppState.DISCONNECTED,
    connState: wifiManager.ConnState.DISCONNECTED,
    channelWidth: wifiManager.WifiChannelWidth.WIDTH_20MHZ,
    wifiStandard: wifiManager.WifiStandard.WIFI_STANDARD_UNDEFINED,
    supportedWifiCategory: wifiManager.WifiCategory.DEFAULT,
    isHiLinkNetwork: false
  }

  async scan() {
    if (!this.isScanning) {
      return; // 如果不需要扫描，则直接返回
    } else {
      try{
        let result = await wifiManager.getScanInfoList();
        console.log(TAG, `scan info call back: ${ result.length }`)
        result.forEach(item => {
          if (item.ssid) {
            this.wifiList.push({
              ssid: item.ssid,
              bssid: item.bssid,
              bssidType: item.bssidType,
              capabilities: item.capabilities,
              securityType: item.securityType,
              rssi: item.rssi,
              band: item.band,
              frequency: item.frequency,
              channelWidth: item.channelWidth,
              centerFrequency0: item.centerFrequency0,
              centerFrequency1: item.centerFrequency1,
              infoElems: item.infoElems,
              timestamp: item.timestamp,
              supportedWifiCategory: item.supportedWifiCategory,
              isHiLinkNetwork: item.isHiLinkNetwork,
            });
          }
        });
        this.wifiList = [...this.wifiList];
        console.log(TAG, "wifiList:" + JSON.stringify(this.wifiList))
      } catch (error) {
        console.error(TAG, `Error scanning Wi-Fi: ${error}`);
      }

      if (this.isScanning) { // 再次检查是否还需要继续扫描
        setTimeout(() => {
          this.scan()
        }, 2000)
      }
    }
  }

  getLinkedInfo() {
    wifiManager.getLinkedInfo((err, linkedInfo) => {
      if (err) {
        console.log(TAG, `getLinkedInfo err: ${ JSON.stringify(err) }`)
        return;
      }
      console.log(TAG, `linkedInfo: ${ JSON.stringify(linkedInfo) }`)
      if (linkedInfo === null || linkedInfo.bssid === '') {
        this.isLinked = false
        this.linkedInfo = {
          ssid: "",
	  bssid: "",
          networkId: 0,
          rssi: 0,
          band: 0
        } as wifiManager.WifiLinkedInfo
        return;
      }
      this.isLinked = true
      this.linkedInfo = linkedInfo as wifiManager.WifiLinkedInfo;
      console.log("getLinkedInfo this.linkedInfo:" + this.linkedInfo);
    })
  }

  addListener() {
    wifiManager.on('wifiConnectionChange', state => {
      console.log(TAG, `wifiConnectionChange: ${ state }`)
      this.getLinkedInfo()
    })
    wifiManager.on('wifiStateChange', state => {
      console.log(TAG, `wifiStateLisener state: ${ state }`)
      if (state === 1) { //0: inactive, 1: active, 2: activating, 3: de - activating
        this.scan();
      }
    })
  }

  aboutToAppear() {
    if (wifiManager.isWifiActive()) {
      console.log(TAG, 'wifi is active')
      this.isSwitchOn = true
      this.isScanning = true; // 在页面出现时开始扫描
      // wifiManager.startScan()
      this.scan()
      this.getLinkedInfo()
    } else {
      this.isSwitchOn = false;
    }
    this.addListener()
  }

  build() {
    Column() {
      Stack({ alignContent: Alignment.TopStart }) {
        TitleBar({ detail: "wlan" })
      }

      Row() {
        Text($r('app.string.wlan'))
          .fontSize(22)
          .fontWeight(FontWeight.Bold)
          .layoutWeight(1)
          .align(Alignment.TopStart)
        Column() {
          Toggle({ type: ToggleType.Switch, isOn: this.isSwitchOn })
            .onChange(async (isOn: boolean) => {
              console.log(TAG, `wifi swtich is: ${ isOn }`)
              this.wifiList = []
              if (isOn) {
                try {
                  this.isSwitchOn = true;
                  this.isScanning = true;
                  await wifiManager.enableWifi();
                  // 延迟执行startScan，确保WiFi服务已经准备好
                  setTimeout(() => {
                    this.scan();
                  }, 2000);
                } catch (error) {
                  console.error(TAG, `Failed to enable Wi-Fi: ${error}`);
                }
              } else {
                this.isSwitchOn = false;
                this.isLinked = false;
                this.isScanning = false;
                try {
                  await wifiManager.disconnect();
                  await wifiManager.disableWifi();
                } catch (error) {
                  console.error(TAG, `Failed to disable Wi-Fi: ${error}`);
                }
                this.wifiList = [];
              }
            })
        }
      }
      .width(ConfigData.WH_95_100)

      if (this.isSwitchOn) {
        if (this.isLinked) {
          Text($r('app.string.wlanIsConnected'))
            .fontSize(22)
            .width(ConfigData.WH_95_100)
            .align(Alignment.TopStart)
          Row() {
            Text(this.linkedInfo.ssid)
              .fontSize(20)
              .fontColor(Color.Black)
              .layoutWeight(1)
            Text($r('app.string.wlanIsConnected'))
              .fontSize(18)
              .fontColor(Color.Black)
          }
          .width(ConfigData.WH_95_100)
          .padding(10)
          .margin(10)
          .border({ radius: 15, color: Color.Gray, width: 1 })
          .backgroundColor(Color.White)
        }
        AvailableWifi({ wifiList: $wifiList, linkedInfo: $linkedInfo })
      }
    }
    .size({ width: ConfigData.WH_100_100, height: ConfigData.WH_100_100 })
    .backgroundColor('#F5F5F5')
  }

  aboutToDisappear() {
    this.isScanning = false; // 设置标志，告诉scan方法停止新的扫描
    this.isSwitchOn = false
    wifiManager.off('wifiConnectionChange')
    wifiManager.off('wifiStateChange')
  }
}