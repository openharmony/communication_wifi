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

/**
 * P2pModel api Test Page Of wifi test
 */

// 定义 callback 的类型。这里假设它的参数是一个 WifiP2pGroupInfo 类型的数组
type CallbackType1 = (groups: wifi.WifiP2pGroupInfo[]) => void;
type CallbackType2 = (groups: wifi.WifiP2pDevice[]) => void;
const TAG = "[P2pModel]"

export class P2pModel {
  getP2pPeerDevices(callback: CallbackType2) {
    console.log(TAG , 'scanP2p begin')
    try {
      wifi.getP2pPeerDevices((err , wifiP2pDevice) => {
        let p2pList: wifi.WifiP2pDevice[] = []
        if ( err ) {
          console.log(TAG , `scan p2p info err: ${ JSON.stringify(err) }`)
          callback(p2pList)
          return
        }
        console.log(TAG , `scan p2p info call back: ` + JSON.stringify(wifiP2pDevice))
        let len = Object.keys(wifiP2pDevice).length;
        for ( let i = 0 ; i < len ; ++i ) {
          p2pList.push({
            deviceName : wifiP2pDevice[ i ].deviceName ,
            deviceAddress : wifiP2pDevice[ i ].deviceAddress ,
            primaryDeviceType : wifiP2pDevice[ i ].primaryDeviceType ,
            deviceStatus : wifiP2pDevice[ i ].deviceStatus ,
            groupCapabilitys : wifiP2pDevice[ i ].groupCapabilitys ,
          })
          console.log(TAG , 'wifiP2pDevice:' + JSON.stringify(wifiP2pDevice[ i ]))
          console.log(TAG , 'p2pList:' + JSON.stringify(p2pList))
        }
        callback(p2pList)
      })
    } catch( error ) {
      console.log(TAG , `Failed to testGetP2pPeerDevicesCallback. message: ${ error.message }, code: ${ error.code }`)
    }
  }

  getCurrentGroup(callback: CallbackType1) {
    console.log(TAG , 'scanP2pGroup begin')
    wifi.getCurrentGroup((err , result) => {
      let p2pGroupList: wifi.WifiP2pGroupInfo[] = []; // 初始化数组
      if ( err ) {
        console.log(TAG , `scan info err: ${ JSON.stringify(err) }`)
        callback(p2pGroupList); // 在错误回调中返回空数组
        return
      }
      // 如果result是一个对象而不是数组
      let groupInfo: wifi.WifiP2pGroupInfo = {
        isP2pGo : result.isP2pGo ,
        ownerInfo : result.ownerInfo ,
        passphrase : result.passphrase ,
        interface : result.interface ,
        groupName : result.groupName ,
        networkId : result.networkId ,
        frequency : result.frequency ,
        clientDevices : result.clientDevices ,
        goIpAddress : result.goIpAddress ,
      };
      p2pGroupList.push(groupInfo);
      callback(p2pGroupList)
    })
  }

  connectP2p(p2pScanInfo: wifi.WifiP2pDevice) {
    prompt.showToast({ message : 'connecting' })
    console.log(TAG , `connect deviceAddress=${ p2pScanInfo.deviceAddress }`)
    console.log(TAG , `p2pScanInfo:` + JSON.stringify(p2pScanInfo))
    let config: wifi.WifiP2PConfig = {
      deviceAddress : p2pScanInfo.deviceAddress ,
      netId : - 2 ,
      passphrase : "" , //wifiP2pGroupInfo.passphrase
      groupName : "" , //wifiP2pGroupInfo.groupName
      goBand : 0
    }

    if ( wifi.p2pConnect(config) ) {
      console.log(TAG , `connectP2P success`)
      wifi.createGroup(config)
    } else {
      console.log(TAG , `connectP2P fail`)
    }
  }
}