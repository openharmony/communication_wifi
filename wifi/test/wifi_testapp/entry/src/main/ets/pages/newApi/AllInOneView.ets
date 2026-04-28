/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import hilog from '@ohos.hilog';
import ConfigData from '../../Utils/ConfigData';
import { wifiManager} from '@kit.ConnectivityKit';
import { ChangeNameView} from './ChangeNameView';
import { NormalNav} from './components/NormalNav';
import { JSON} from '@kit.ArkTS';
import { CreateGroupView} from './CreateGroupView';
import { GlobalThis} from '../../Utils/globalThis';
import { common} from '@kit.AbilityKit';

const TAG = '[AllInOneView]'

const ctx = GlobalThis.getInstance().getContext('context') as common.UIAbilityContext

/*CONNECTED	0	连接状态。
INVITED	1	邀请状态。
FAILED	2	失败状态。
AVAILABLE	3	可用状态。
UNAVAILABLE	4	不可用状态。*/
const P2PDeviceStatusInfo = [
  $r('app.string.status_connected'),
  $r('app.string.status_invite'),
  $r('app.string.status_fail'),
  $r('app.string.status_available'),
  $r('app.string.status_unavailable')]
@Observed
export class P2PDevice {
  name: string
  address: string = ''
  status: number = 0

  constructor(name: string){
    this.name = name
    this.status = 0
  }

  static from(d: wifiManager.WifiP2pDevice):P2PDevice {
    let res = new P2PDevice(d.deviceName)
    res.name = d.deviceName
    res.address = d.deviceAddress
    res.status = d.deviceStatus
    return res
  }
}

@Observed
class P2PGroup {
  // 群组名称
  name: string
  networkId: number
  // 是否为群主
  /*isGo: boolean
  // 群主设备信息
  ownerInfo: P2PDevice
  // 密钥
  passphrase: string
  // 接口名称
  interface: string
  // 网络id
  networkId: number
  // 群组频率
  frequency: number
  // 接入设备列表
  clientDevices: P2PDevice[]
  // 群主ip地址
  goIpAddress: string*/


  constructor(group: wifiManager.WifiP2pGroupInfo){
    this.name = group.groupName
    this.networkId = group.networkId
    /*this.isGo = group.isP2pGo
    this.ownerInfo = P2PDevice.from(group.ownerInfo)
    this.passphrase = group.passphrase
    this.interface = group.interface
    this.networkId = group.networkId
    this.frequency = group.frequency
    this.clientDevices = group.clientDevices.map(P2PDevice.from)
    this.goIpAddress = group.goIpAddress*/
  }

  static from(g: wifiManager.WifiP2pGroupInfo): P2PGroup {
    let res = new P2PGroup(g)
    return res
  }
}


enum P2PConnectStatus {
  Normal,
  Connecting,
  CancelConnecting,
  Disconnecting
}

@Entry
@Component
export struct AllInOneView {

  @Provide('p2pPathInfo') pathInfo:NavPathStack = new NavPathStack()
  @State availableDevices: P2PDevice[] = []
  @State localDevice: P2PDevice | null = null
  @State allGroup: P2PGroup[] = []
  @State isP2pDiscoverEnable:boolean = true
  @State p2pLinkedInfo: wifiManager.WifiP2pLinkedInfo | null = null
  @State currentLinkedDevice: P2PDevice[] = []
  connectStatus: P2PConnectStatus = P2PConnectStatus.Normal

  async aboutToAppear() {
    this.addP2PListener()
    try {
      wifiManager.startDiscoverDevices()
    } catch (e){
      JSON.stringify(e)
    }
    try {
      this.p2pLinkedInfo  = await wifiManager.getP2pLinkedInfo()
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s %{public}s', TAG, 'linkedInfo: ', JSON.stringify(this.p2pLinkedInfo))
    } catch (e){
      hilog.info(0x1500, 'wifiTestApp', '%{public}s', JSON.stringify(e))
    }
    try {
      let curGp = await wifiManager.getCurrentGroup()
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `currentGroup: ${JSON.stringify(curGp)}`)
    } catch (e){
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `getCurrentGroup Error ${JSON.stringify(e)}`)
    }
    try {
      let gps = await wifiManager.getP2pGroups()
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s %{public}s', TAG, 'Groups: ', JSON.stringify(gps))
      this.allGroup = gps.map(P2PGroup.from)
      let ldv = await wifiManager.getP2pLocalDevice()
      this.localDevice = P2PDevice.from(ldv)
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, JSON.stringify(this.localDevice))
    } catch (e){
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s %{public}s', TAG, 'err getP2pLocalDevice', JSON.stringify(e))
    }
  }

  aboutToDisappear(): void {
    this.removeP2PListener()
  }

  addP2PListener() {
    wifiManager.on('p2pDeviceChange', () => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'p2pDeviceChange')
    })
    wifiManager.on('p2pPersistentGroupChange', async () => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'p2pPersistentGroupChange')
      let gps = await wifiManager.getP2pGroups()
      this.allGroup = gps.map(P2PGroup.from)
    })
    wifiManager.on('p2pDiscoveryChange', (status) => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `p2pDiscoveryChange: ${status}`)
      this.isP2pDiscoverEnable = (status === 1)
    })
    wifiManager.on('p2pPeerDeviceChange', (_: wifiManager.WifiP2pDevice[]) => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s %{public}s', TAG, 'p2pPeerDeviceChange:', JSON.stringify(_))
      let availDevice = _.filter(e => e.deviceStatus !== wifiManager.P2pDeviceStatus.CONNECTED)
      this.availableDevices = availDevice.map(P2PDevice.from)
      this.currentLinkedDevice = _.filter(e => e.deviceStatus === wifiManager.P2pDeviceStatus.CONNECTED).map(P2PDevice.from)
     })
    wifiManager.on('p2pConnectionChange', async (result: wifiManager.WifiP2pLinkedInfo) => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s %{public}s', TAG, 'p2pConnectionChange', JSON.stringify(result))
      let device = await wifiManager.getP2pLocalDevice()
      this.localDevice = P2PDevice.from(device)
      if (result.connectState === 0){
        wifiManager.startDiscoverDevices()
      } else {
        let gp = await wifiManager.getCurrentGroup()
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s %{public}s', TAG, 'currentGroup:', JSON.stringify(gp))
      }

    })

  }

  removeP2PListener() {
    try {
      wifiManager.off('p2pPersistentGroupChange')
      wifiManager.off('p2pDiscoveryChange')
      wifiManager.off('p2pPeerDeviceChange')
      wifiManager.off('p2pConnectionChange')
    } catch (e){
      hilog.info(0x1500, 'wifiTestApp', '%{public}s', `wifiManager.off Error: ${JSON.stringify(e)}`)
    }

  }

  @Builder localDeviceHeaer() {
    Row() {
      Text($r('app.string.my_device'))
        .fontWeight(FontWeight.Bold)
    }.height(ConfigData.VP_60)
  }

  @Builder connectedDeviceHeader() {
    Row() {
      Text($r('app.string.connected_device'))
        .fontWeight(FontWeight.Bold)
    }.height(ConfigData.VP_60)
  }

  @Builder deviceHeader() {
    Row() {
      Text($r('app.string.available_device'))
        .fontWeight(FontWeight.Bold)
    }
    .height(ConfigData.VP_60)
  }

  @Builder groupHeader() {
    Row() {
      Text($r('app.string.saved_group'))
        .fontWeight(FontWeight.Bold)
    }
    .height(ConfigData.VP_60)
  }

  build() {
    Navigation(this.pathInfo){
      Column() {
        NormalNav({title: $r('app.string.new_api_test_title')})
        Button(this.isP2pDiscoverEnable ? $r('app.string.stop_scan') : $r('app.string.start_scan'))
          .onClick(() => {
            if (this.isP2pDiscoverEnable){
              wifiManager.stopDiscoverDevices()
            }
            wifiManager.startDiscoverDevices()
          })
        Button($r('app.string.create_group_test'))
          .onClick(() => {
            this.pathInfo.pushPath({name: 'createGroup'})
          })
          .margin({top: ConfigData.VP_20})
        List({space: ConfigData.VP_10}){
          if (this.localDevice !== null){
            ListItemGroup({header: this.localDeviceHeaer(), style: ListItemGroupStyle.CARD}){
              ListItem({style: ListItemStyle.CARD}){
                DeviceItemView({device: this.localDevice})
              }.height(ConfigData.VP_110)
              .onClick(() => {
                this.pathInfo.pushPathByName('changeName', null, async () => {
                  hilog.info(0x1500, 'wifiTestApp', '%{public}s', 'changeNameBack')
                  let device = await wifiManager.getP2pLocalDevice()
                  this.localDevice = P2PDevice.from(device)
                }, true)
              })
            }
          }
          if (this.currentLinkedDevice.length > 0){
            ListItemGroup({header: this.connectedDeviceHeader(), style: ListItemGroupStyle.CARD}){
              ForEach(this.currentLinkedDevice, (device: P2PDevice) => {
                ListItem({style: ListItemStyle.CARD}){
                  DeviceItemView({device: device})
                }.height(ConfigData.VP_110)
                .onClick(() => {
                  this.disconnect(device)
                })
              })
            }
          }
          ListItemGroup({header: this.deviceHeader, style: ListItemGroupStyle.CARD}){
            ForEach(this.availableDevices, (device: P2PDevice) => {
              ListItem({style: ListItemStyle.CARD}){
                DeviceItemView({device: device})
              }
              .height(ConfigData.VP_110)
              .onClick(async () => {
                hilog.info(0x1500, 'wifiTestApp', '%{public}s', `device.status === ${device.status}`)
                if (device.status === wifiManager.P2pDeviceStatus.INVITED){
                  this.cancelConnect(device)
                } else {
                  await this.connectToDevice(device)
                }

              })
            })
          }.divider({strokeWidth: ConfigData.VP_2, startMargin: ConfigData.VP_10, endMargin: ConfigData.VP_10})
          if (this.allGroup.length > 0){
            ListItemGroup({header: this.groupHeader, style: ListItemGroupStyle.CARD}){
              ForEach(this.allGroup, (group: P2PGroup) => {
                ListItem({style: ListItemStyle.CARD}){
                  GroupItemView({group: group})
                }.onClick(() => {
                  this.deleteGroup(group)
                })
              })
            }
          }
        }
        .layoutWeight(1)
        .margin({top: ConfigData.VP_10})
      }
      .backgroundColor($r("app.color.ohcc_hex_f2f2f2"))
      .width(ConfigData.WH_100_100)
      .height(ConfigData.WH_100_100)
    }
    .hideTitleBar(true)
    .navDestination(this.routeMap)

  }

  cancelConnect(device: P2PDevice){
    let ctx = GlobalThis.getInstance().getContext('context')
    let message = ctx!.resourceManager.getStringSync($r("app.string.cancel_connect_alert_str"), device.name)
    AlertDialog.show({
      alignment: DialogAlignment.Bottom,
      title: $r('app.string.cancel_invite'),
      message,
      primaryButton: {
        value: $r('app.string.cancel_button'),
        action: () => {}
      },
      secondaryButton: {
        value: $r('app.string.confirm_button'),
        action: () => {
          try {
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `p2pCancelConnect`)
            wifiManager.p2pCancelConnect()
          } catch (e){
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "p2pCancelConnect Error:" + JSON.stringify(e))
          }
        }
      }
    })
  }

  disconnect(device: P2PDevice){
    let ctx = GlobalThis.getInstance().getContext('context')
    let message = ctx!.resourceManager.getStringSync($r("app.string.disconnect_alert_content"), device.name)
    AlertDialog.show({
      alignment: DialogAlignment.Bottom,
      title: $r('app.string.disconnect_alert_title'),
      message,
      primaryButton: {
        value: $r('app.string.cancel_button'),
        action: () => {
          hilog.info(0x1500, 'wifiTestApp', '%{public}s', "cancel disconnect")
        }
      },
      secondaryButton: {
        value: $r('app.string.confirm_button'),
        action: () => {
          try {
            wifiManager.removeGroup()
          } catch (e){
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "removeGroup err: " + JSON.stringify(e))
          }
        }
      }
    })
  }

  deleteGroup(group: P2PGroup){
    AlertDialog.show({
      alignment: DialogAlignment.Bottom,
      title: $r("app.string.abandon_group_alert_title"),
      message: '',
      primaryButton: {
        value: $r("app.string.cancel_button"),
        action: () => {}
      },
      secondaryButton: {
        value: $r('app.string.confirm_button'),
        action: () => {
          wifiManager.deletePersistentGroup(group.networkId)
        }
      }
    })
  }

  async connectToDevice(device: P2PDevice){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', 'connect to device:', JSON.stringify(device))
    let config:wifiManager.WifiP2PConfig = {
      deviceAddress: device.address,
      netId:-1,
      passphrase:"",
      groupName: "",
      goBand:0,
    }

    try {
      wifiManager.p2pConnect(config)
      wifiManager.startDiscoverDevices()
    } catch (e){
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s %{public}s', TAG, 'connect and create group error:', JSON.stringify(e))
    }
  }

  @Builder routeMap(name: string){
    if (name === 'changeName'){
      ChangeNameView()
    } else if (name === 'createGroup'){
      CreateGroupView()
    }
  }
}

@Component
export struct DeviceItemView {

  @ObjectLink device: P2PDevice
  @State deviceNameTitle: string = ''
  @State deviceAddrTitle: string = ''
  @State deviceStatusTitle: string = ''

  async aboutToAppear() {
    this.deviceNameTitle = await ctx.resourceManager.getStringValue($r('app.string.device_name'))
    this.deviceAddrTitle = await ctx.resourceManager.getStringValue($r('app.string.device_addr'))
    this.deviceStatusTitle = await ctx.resourceManager.getStringValue($r('app.string.device_status'))
  }

  build() {
    Row() {
      Column({space: ConfigData.VP_10}){
        Text(`${this.deviceNameTitle}：${this.device.name}`)
        Text(`${this.deviceAddrTitle}：${this.device.address}`)
        Text(`${this.deviceStatusTitle}：${ctx.resourceManager.getStringSync(P2PDeviceStatusInfo[this.device.status])}`)
      }.alignItems(HorizontalAlign.Start)
      Blank().layoutWeight(1)
      if (this.device.status === wifiManager.P2pDeviceStatus.INVITED){
        LoadingProgress()
          .width(ConfigData.VP_40)
          .height(ConfigData.VP_40)
          .enableLoading(true)
      }
    }
    .padding({left: ConfigData.VP_15, right: ConfigData.VP_15})
  }
}

@Component
struct GroupItemView {
  @ObjectLink group: P2PGroup
  @State groupTitle: string = ''

  async  aboutToAppear() {
    this.groupTitle = await ctx.resourceManager.getStringValue($r('app.string.group_name'))
  }

  build() {
    Row() {
      Column({space: ConfigData.VP_10}){
        Text(`${this.groupTitle}：${this.group.name}`)
      }.alignItems(HorizontalAlign.Start)
      Blank().layoutWeight(1)
    }
    .padding({left: ConfigData.VP_15, right: ConfigData.VP_15})
  }
}