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

import prompt from '@ohos.prompt'
import wifi from '@ohos.wifi'
import wifiManager from '@ohos.wifiManager';

// 定义 callback 的类型。这里假设它的参数是一个 WifiP2pGroupInfo 类型的数组
type CallbackType = (groups: wifi.WifiScanInfo[]) => void;

/**
 * WifiModel Page Of wifi test
 */
interface IpInfo {
  key: Resource,
  value: string
}

const TAG = "[wifiModel]"

export class WifiModel {
  getScanInfos(callback: CallbackType) {
    console.log(TAG , 'scanWifi begin')
    wifi.getScanInfos((err , result) => {
      let wifiList: wifi.WifiScanInfo[] = []
      if ( err ) {
        console.log(TAG , `scan info err: ${ JSON.stringify(err) }`)
        callback(wifiList)
        return
      }
      console.log(TAG , `scan info call back: ${ result.length }`)
      for ( let i = 0 ; i < result.length ; ++i ) {
        wifiList.push({
          ssid : result[ i ].ssid ,
          bssid : result[ i ].bssid ,
          capabilities : result[ i ].capabilities ,
          securityType : result[ i ].securityType ,
          rssi : result[ i ].rssi ,
          band : result[ i ].band ,
          frequency : result[ i ].frequency ,
          channelWidth : result[ i ].channelWidth ,
          timestamp : result[ i ].timestamp ,
        })
      }
      callback(wifiList)
    })
  }

  connectNetwork(scanInfo: wifiManager.WifiDeviceConfig , psw: string) {
    prompt.showToast({ message : 'connecting' })
    console.log(TAG , `connectNetwork bssid=${ scanInfo.bssid }`)
    let deviceConfig: wifiManager.WifiDeviceConfig = scanInfo
    try {
      wifiManager.connectToDevice(deviceConfig)
      console.log(TAG , `connectToDevice success`)
    } catch( error ) {
      console.log(TAG , `connectToDevice fail. message: ${ error.message }, code: ${ error.code }`)
    }
  }

  resolveIP(ip: number) {
    let address: string = ip.toString()
    if ( address === '0' ) {
      return '00:00:000:000'
    } else {
      console.log(" address /= 0")
    }
    address.substring(0 , 2)
    return `${ address.substring(0 , 2) }:${ address.substring(2 , 4) }:${ address.substring(4 , 7) }:${ address.substring(7 , 10) }`
  }

  getIpInfo() {
    let ipInfoList: IpInfo[] = []
    let ipInfo = wifi.getIpInfo()
    console.log(`${ TAG } getIpInfo=${ JSON.stringify(ipInfo) }`)
    ipInfoList.push({ key : $r('app.string.ip_address') , value : this.resolveIP(ipInfo.ipAddress) })
    ipInfoList.push({ key : $r('app.string.gate_way') , value : this.resolveIP(ipInfo.gateway) })
    ipInfoList.push({ key : $r('app.string.net_mask') , value : this.resolveIP(ipInfo.netmask) })
    ipInfoList.push({ key : $r('app.string.primary_dns') , value : this.resolveIP(ipInfo.primaryDns) })
    ipInfoList.push({ key : $r('app.string.second_dns') , value : this.resolveIP(ipInfo.secondDns) })
    ipInfoList.push({ key : $r('app.string.server_ip') , value : this.resolveIP(ipInfo.serverIp) })
    ipInfoList.push({ key : $r('app.string.lease_duration') , value : ipInfo.leaseDuration.toString() })
    return ipInfoList
  }

  getCountryCode() {
    let countryCodeList: IpInfo[] = []
    let countryCode = wifi.getCountryCode()
    countryCodeList.push({ key : $r('app.string.country_code') , value : countryCode })
    return countryCodeList
  }

  getFeatureSupport() {
    let featureSupportedList: IpInfo[] = []
    featureSupportedList.push({
      key : $r('app.string.infrastructure_feature') ,
      value : wifi.isFeatureSupported(0x0001).toString()
    })
    featureSupportedList.push({
      key : $r('app.string.ghz_feature') ,
      value : wifi.isFeatureSupported(0x0002).toString()
    })
    featureSupportedList.push({
      key : $r('app.string.gas_anqp_feature') ,
      value : wifi.isFeatureSupported(0x0004).toString()
    })
    featureSupportedList.push({
      key : $r('app.string.wifi_direct') ,
      value : wifi.isFeatureSupported(0x0008).toString()
    })
    featureSupportedList.push({
      key : $r('app.string.soft_ap') ,
      value : wifi.isFeatureSupported(0x0010).toString()
    })
    featureSupportedList.push({
      key : $r('app.string.wifi_aware') ,
      value : wifi.isFeatureSupported(0x0040).toString()
    })
    return featureSupportedList
  }
}