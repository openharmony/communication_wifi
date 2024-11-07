import { wifiManager } from '@kit.ConnectivityKit'
import { ChangeNameView } from './ChangeNameView'
import { NormalNav } from './Components/NormalNav'
import { JSON } from '@kit.ArkTS'


const TAG = '[AllInOneView]'

/*CONNECTED	0	连接状态。
INVITED	1	邀请状态。
FAILED	2	失败状态。
AVAILABLE	3	可用状态。
UNAVAILABLE	4	不可用状态。*/
const P2PDeviceStatusInfo = ['连接状态','邀请状态', '失败状态', '可用状态', '不可用状态']
@Observed
class P2PDevice {
  name: string
  address: string = ''
  status: string = ''

  constructor(name: string) {
    this.name = name
    this.status = ''
  }

  static from(d: wifiManager.WifiP2pDevice):P2PDevice {
    let res = new P2PDevice(d.deviceName)
    res.name = d.deviceName
    res.address = d.deviceAddress
    res.status = P2PDeviceStatusInfo[d.deviceStatus]
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


  constructor(group: wifiManager.WifiP2pGroupInfo) {
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
    } catch (e) {
      JSON.stringify(e)
    }
    try {
      this.p2pLinkedInfo  = await wifiManager.getP2pLinkedInfo()
      console.log(TAG, 'linkedInfo: ', JSON.stringify(this.p2pLinkedInfo))
    } catch (e) {
      console.log(JSON.stringify(e))
    }
    try {
      let curGp = await wifiManager.getCurrentGroup()
      console.log(TAG, `currentGroup: ${JSON.stringify(curGp)}`)
    } catch (e) {
      console.log(TAG, `getCurrentGroup Error ${JSON.stringify(e)}`)
    }
    try {
      let gps = await wifiManager.getP2pGroups()
      console.log(TAG, 'Groups: ', JSON.stringify(gps))
      this.allGroup = gps.map(P2PGroup.from)
      let ldv = await wifiManager.getP2pLocalDevice()
      this.localDevice = P2PDevice.from(ldv)
      console.log(TAG, JSON.stringify(this.localDevice))
    } catch (e) {
      console.log(TAG, 'err getP2pLocalDevice', JSON.stringify(e))
    }
  }

  aboutToDisappear(): void {
    this.removeP2PListener()
  }

  addP2PListener() {
    wifiManager.on('p2pPersistentGroupChange', async () => {
      console.log(TAG, 'p2pPersistentGroupChange')
      let gps = await wifiManager.getP2pGroups()
      this.allGroup = gps.map(P2PGroup.from)
    })
    wifiManager.on('p2pDiscoveryChange', (status) => {
      console.log(TAG, `p2pDiscoveryChange: ${status}`)
      this.isP2pDiscoverEnable = (status === 1)
    })
    wifiManager.on('p2pPeerDeviceChange', (_: wifiManager.WifiP2pDevice[]) => {
      console.log(TAG, 'p2pPeerDeviceChange:', JSON.stringify(_))
      let availDevice = _.filter(e => e.deviceStatus !== wifiManager.P2pDeviceStatus.CONNECTED)
      this.availableDevices = availDevice.map(P2PDevice.from)
      this.currentLinkedDevice = _.filter(e => e.deviceStatus === wifiManager.P2pDeviceStatus.CONNECTED).map(P2PDevice.from)
     })
    wifiManager.on('p2pConnectionChange', async (result: wifiManager.WifiP2pLinkedInfo) => {
      console.log(TAG, 'p2pConnectionChange', JSON.stringify(result))
      if (result.connectState === 0) {
        wifiManager.startDiscoverDevices()
      } else {
        let gp = await wifiManager.getCurrentGroup()
        console.log(TAG, 'currentGroup:', JSON.stringify(gp))
      }
    })

  }

  removeP2PListener() {
    wifiManager.off('p2pPersistentGroupChange')
    wifiManager.off('p2pDiscoveryChange')
    wifiManager.off('p2pPeerDeviceChange')
    wifiManager.off('p2pConnectionChange')
  }

  @Builder localDeviceHeaer() {
    Row() {
      Text('我的设备')
        .fontWeight(FontWeight.Bold)
    }.height(60)
  }

  @Builder connectedDeviceHeader() {
    Row() {
      Text('已连接设备设备')
        .fontWeight(FontWeight.Bold)
    }.height(60)
  }

  @Builder deviceHeader() {
    Row() {
      Text('可用设备')
        .fontWeight(FontWeight.Bold)
    }
    .height(60)
  }

  @Builder groupHeader() {
    Row() {
      Text('已保存的群组')
        .fontWeight(FontWeight.Bold)
    }
    .height(60)
  }

  build() {
    Navigation(this.pathInfo) {
      Column() {
        NormalNav({title: '新接口测试'})
        Button(this.isP2pDiscoverEnable ? '关闭扫描' : '开启扫描')
          .onClick(() => {
            if (this.isP2pDiscoverEnable) {
              wifiManager.stopDiscoverDevices()
            }
            wifiManager.startDiscoverDevices()
          })
        List({ space: 10 }) {
          if (this.localDevice !== null) {
            ListItemGroup({ header: this.localDeviceHeaer(), style: ListItemGroupStyle.CARD }) {
              ListItem({style: ListItemStyle.CARD}) {
                DeviceItemView({device: this.localDevice})
              }.height(110)
              .onClick(() => {
                this.pathInfo.pushPathByName('changeName', null, async () => {
                  console.log('changeNameBack')
                  let device = await wifiManager.getP2pLocalDevice()
                  this.localDevice = P2PDevice.from(device)
                }, true)
              })
            }
          }
          if (this.currentLinkedDevice.length > 0) {
            ListItemGroup({ header: this.connectedDeviceHeader(), style: ListItemGroupStyle.CARD }) {
              ForEach(this.currentLinkedDevice, (device: P2PDevice) => {
                ListItem({style: ListItemStyle.CARD}) {
                  DeviceItemView({device: device})
                }.height(110)
                .onClick(() => {
                  this.disconnect(device)
                })
              })
            }
          }
          ListItemGroup({ header: this.deviceHeader, style: ListItemGroupStyle.CARD }) {
            ForEach(this.availableDevices, (device: P2PDevice) => {
              ListItem({style: ListItemStyle.CARD}) {
                DeviceItemView({device: device})
              }
              .height(110)
              .onClick(async () => {
                if (device.status === '邀请状态') {
                  this.cancelConnect(device)
                } else {
                  await this.connectToDevice(device)
                }

              })
            })
          }.divider({strokeWidth: 2, startMargin: 10, endMargin: 10})
          if (this.allGroup.length > 0) {
            ListItemGroup({ header: this.groupHeader, style: ListItemGroupStyle.CARD }) {
              ForEach(this.allGroup, (group: P2PGroup) => {
                ListItem({ style: ListItemStyle.CARD }) {
                  GroupItemView({group: group})
                }.onClick(() => {
                  this.deleteGroup(group)
                })
              })
            }
          }
        }
        .layoutWeight(1)
        .margin({ top: 10 })
      }
      .backgroundColor('#F2F2F2')
      .width('100%')
      .height('100%')
    }
    .hideTitleBar(true)
    .navDestination(this.routeMap)

  }

  cancelConnect(device: P2PDevice) {
    const message = `是否取消与${device.name}的连接邀请？`
    AlertDialog.show({
      alignment: DialogAlignment.Bottom,
      title: "取消邀请",
      message,
      primaryButton: {
        value: '取消',
        action: () => {}
      },
      secondaryButton: {
        value: '确定',
        action: () => {
          try {
            wifiManager.p2pCancelConnect()
          } catch (e) {
            console.log(TAG, "p2pCancelConnect Error:" + JSON.stringify(e))
          }
        }
      }
    })
  }

  disconnect(device: P2PDevice) {
    const message = `如果断开连接，您与${device.name}的连接将中断`
    AlertDialog.show({
      alignment: DialogAlignment.Bottom,
      title: "断开连接",
      message,
      primaryButton: {
        value: '取消',
        action: () => {
          console.log('取消')
        }
      },
      secondaryButton: {
        value: '确定',
        action: () => {
          try {
            wifiManager.removeGroup()
          } catch (e) {
            console.log("removeGroup err: " + JSON.stringify(e))
          }
        }
      }
    })
  }

  deleteGroup(group: P2PGroup) {
    AlertDialog.show({
      alignment: DialogAlignment.Bottom,
      title: "是否放弃保存所选群组",
      message: '',
      primaryButton: {
        value: '取消',
        action: () => {}
      },
      secondaryButton: {
        value: '确定',
        action: () => {
          try {
            wifiManager.deletePersistentGroup(group.networkId)
          } catch (e) {
            console.log("removeGroup err: " + JSON.stringify(e))
          }
        }
      }
    })
  }

  async connectToDevice(device: P2PDevice) {
    console.log('connect to device:', JSON.stringify(device))
    let config:wifiManager.WifiP2PConfig = {
      deviceAddress: device.address,
      netId:-2,
      passphrase:"",
      groupName: "",
      goBand:0,
    }

    try {
      wifiManager.p2pConnect(config)
      wifiManager.startDiscoverDevices()
    } catch (e) {
      console.log(TAG, 'connect and create group error:', JSON.stringify(e))
    }
  }

  @Builder routeMap(name: string) {
    if (name === 'changeName') {
      ChangeNameView()
    }
  }
}

@Component
struct DeviceItemView {

  @ObjectLink device: P2PDevice

  build() {
    Row() {
      Column({space: 10}) {
        Text(`设备名称：${this.device.name}`)
        Text(`设备地址：${this.device.address}`)
        Text(`设备状态：${this.device.status}`)
      }.alignItems(HorizontalAlign.Start)
      Blank().layoutWeight(1)
      if (this.device.status === '邀请状态') {
        LoadingProgress()
          .width(40)
          .height(40)
      .enableLoading(true)
    }
    }
    .padding({left: 15, right: 15})
  }
}

@Component
struct GroupItemView {

  @ObjectLink group: P2PGroup

  build() {
    Row() {
      Column({space: 10}) {
        Text(`组名称：${this.group.name}`)
      }.alignItems(HorizontalAlign.Start)
      Blank().layoutWeight(1)
    }
    .padding({left: 15, right: 15})
  }
}