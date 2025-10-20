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
 
import { wifiManager } from "@kit.ConnectivityKit"
import { promptAction } from "@kit.ArkUI"
import { DeviceItemView, P2PDevice } from "./AllInOneView"
import { NormalNav } from "./Components/NormalNav"

const TAG = "CreateGroupView"

interface GroupInfo {
  groupName: string,
  password: string,
  goAddr: string,
  goName: string
}

PersistentStorage.persistProp<GroupInfo>('groupInfo', undefined)

@Component
export struct CreateGroupView {

  @State showCreateGroupSheet: boolean = false
  @State showConnectTestSheet: boolean = false
  @State groupName: string = ''
  @State pwd: string = ''
  @State connectPwd: string = ''
  @State connectGroupName: string = ''
  @State allDevices: P2PDevice[] = []
  @StorageLink('groupInfo') groupInfo?: GroupInfo = undefined
  selectDevice: P2PDevice | null = null
  pwdInputDialog: CustomDialogController = new CustomDialogController({
    builder: CustomInputDialog({
      title: this.selectDevice === null ? '' : this.selectDevice.name,
      pwd: this.connectPwd,
      gpName: this.connectGroupName,
      cancel: () => {
        this.pwdInputDialog.close()
      },
      confirm: () => {
        this.pwdInputDialog.close()
        this.startConnect()
      }
    }),
    width: 300,
    height: 250
  })

  async aboutToAppear() {
    wifiManager.on('p2pPeerDeviceChange', (ds: wifiManager.WifiP2pDevice[]) => {
      this.allDevices = ds.map(P2PDevice.from)
    })
    wifiManager.on('p2pDiscoveryChange', (status: number) => {
      if (status === 0) {
        wifiManager.startDiscoverDevices()
      }
    })
    try {
      wifiManager.startDiscoverDevices()
    } catch (e) {
      console.log(TAG, `startDiscoverDevices Error: ${JSON.stringify(e)}`)
    }
  }

  aboutToDisappear(): void {
    wifiManager.off('p2pPeerDeviceChange')
    wifiManager.off('p2pDiscoveryChange')
  }

  @Builder
  createGroupSheetBuilder() {
    Column({space: 20}) {
      TextInput({text: $$this.groupName, placeholder: $r('app.string.input_create_name_tip')})
      TextInput({text:$$this.pwd, placeholder: $r('app.string.input_create_pwd_tip')})
      Row({ space: 20}) {
        Button($r('app.string.confirm_button'),{type: ButtonType.Normal})
          .height(40)
          .layoutWeight(1)
          .onClick(() => {
            if (this.groupName.length <= 0 || this.pwd.length <= 0) {
              promptAction.showToast({message: $r('app.string.input_pwd_name_tip')})
            } else {
              this.showCreateGroupSheet = false
              this.createGroup()
            }
          })
        Button($r('app.string.cancel_button'),{type: ButtonType.Normal})
          .height(40)
          .layoutWeight(1)
          .onClick(() => {
            this.showCreateGroupSheet = false
          })
      }.width('100%')
    }
    .padding(20)
  }

  @Builder
  connectToGroupSheetBuilder() {
    Column() {
      List() {
        ForEach(this.allDevices, (device: P2PDevice) => {
          ListItem() {
            DeviceItemView({device: device})
          }.onClick(() => {
            this.selectDevice = device
            this.showConnectTestSheet = false
            this.pwdInputDialog.open()
          })
        })
      }.divider({strokeWidth: 1, color: Color.Gray})
    }
    .padding(20)
  }

  build() {
    NavDestination() {
      Column({space: 20}) {
        NormalNav({title: $r('app.string.create_group_test_title')})
        Button($r('app.string.create_group'))
          .bindSheet($$this.showCreateGroupSheet, this.createGroupSheetBuilder(), {
            showClose: false,
          })
          .onClick(() => {
            this.showCreateGroupSheet = true
          })
        Button($r('app.string.connect_group_test'))
          .bindSheet($$this.showConnectTestSheet, this.connectToGroupSheetBuilder(), {
            showClose: false
          })
          .onClick(() => {
            this.showConnectTestSheet = true
          })
        if (this.groupInfo) {
          Column({space: 10}) {
            Text($r('app.string.created_group_title'))
              .fontWeight(FontWeight.Bolder)
            Text() {
              Span($r('app.string.group_name'))
              Span(' : ')
              Span(this.groupInfo.groupName)
            }
            Text() {
              Span($r('app.string.device_name'))
              Span(' : ')
              Span(this.groupInfo.goName)
            }
            Text() {
              Span($r('app.string.pwd_title'))
              Span(' : ')
              Span(this.groupInfo.password)
            }

            Button($r('app.string.delete_group_title')).onClick(() => {
              try {
                wifiManager.removeGroup()
                this.groupInfo = undefined
              } catch (e) {
                console.log(TAG, `removeGroup error: ${JSON.stringify(e)}`)
              }
            })
          }.width('90%')
          .border({width: 2})
          .padding(10)
        }
      }.padding(20)
    }
    .hideTitleBar(true)
  }

  async createGroup() {
    try {
      let deviceInfo = await wifiManager.getP2pLocalDevice()
      let config:wifiManager.WifiP2PConfig = {
        deviceAddress: deviceInfo.deviceAddress,
        netId: -1,
        passphrase: this.pwd,
        groupName: this.groupName,
        goBand: 0
      }
      console.log(`deviceAddress: ${config.deviceAddress}, netId: ${config.netId}, pwd: ${config.passphrase}, gpname: ${config.groupName}, goBand: ${config.goBand}`)
      wifiManager.createGroup(config)
      this.groupInfo = {
        groupName: this.groupName,
        password: this.pwd,
        goAddr: deviceInfo.deviceAddress,
        goName: deviceInfo.deviceName
      }
    } catch (e) {
      console.log(TAG, `createGroup Error: ${JSON.stringify(e)}`)
    }
  }

  startConnect() {
    if (this.selectDevice === null ) return
    let config:wifiManager.WifiP2PConfig = {
      deviceAddress: this.selectDevice.address,
      netId: -1,
      passphrase: this.connectPwd,
      groupName: this.connectGroupName,
      goBand: 0
    }
    console.log(TAG, `startConnect config: ${JSON.stringify(config)}`)
    try {
      wifiManager.p2pConnect(config)
    } catch (e) {
      console.log(`p2pConnect Error: ${JSON.stringify(e)}`)
    }
  }
}

@CustomDialog
struct CustomInputDialog {
  controller?: CustomDialogController
  cancel: () => void = () => {}
  confirm: () => void = () => {}
  title: string = ''
  @Link pwd: string
  @Link gpName: string
  build() {
    Column({space: 20}) {
      Text(this.title)
      TextInput({text: $$this.gpName, placeholder: $r('app.string.input_create_name_tip')})
      TextInput({text: $$this.pwd,placeholder: $r('app.string.input_create_pwd_tip')})
      Row({space: 20}) {
        Button($r('app.string.confirm_button'), {
          type: ButtonType.Normal
        })
          .layoutWeight(1)
          .onClick(() => {
          this.confirm()
        })
        Button($r('app.string.cancel_button'), {
          type: ButtonType.Normal
        })
          .layoutWeight(1)
          .onClick(() => {
          this.cancel()
        })
      }
    }
    .padding(20)
  }
}