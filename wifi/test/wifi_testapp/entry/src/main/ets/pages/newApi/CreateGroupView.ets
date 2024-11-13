import { wifiManager } from "@kit.ConnectivityKit"
import { promptAction } from "@kit.ArkUI"
import { DeviceItemView, P2PDevice } from "./AllInOneView"
import { NormalNav } from "./Components/NormalNav"

const TAG = "CreateGroupView"

@Component
export struct CreateGroupView {

  @State showCreateGroupSheet: boolean = false
  @State showConnectTestSheet: boolean = false
  @State groupName: string = ''
  @State pwd: string = ''
  @State connectPwd: string = ''
  @State allDevices: P2PDevice[] = []
  selectDevice: P2PDevice | null = null
  pwdInputDialog: CustomDialogController = new CustomDialogController({
    builder: CustomInputDialog({
      title: this.selectDevice === null ? '' : this.selectDevice.name,
      pwd: this.connectPwd,
      cancel: () => {
        this.pwdInputDialog.close()
      },
      confirm: () => {
        this.pwdInputDialog.close()
        this.startConnect()
      }
    }),
    width: 300,
    height: 200
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
      }.padding(20)
    }
    .hideTitleBar(true)
  }

  async createGroup() {
    try {
      let deviceInfo = await wifiManager.getP2pLocalDevice()
      let config:wifiManager.WifiP2PConfig = {
        deviceAddress: deviceInfo.deviceAddress,
        netId: -2,
        passphrase: this.pwd,
        groupName: this.groupName,
        goBand: 0
      }
      console.log(`deviceAddress: ${config.deviceAddress}, netId: ${config.netId}, pwd: ${config.passphrase}, gpname: ${config.groupName}, goBand: ${config.goBand}`)
      wifiManager.createGroup(config)
    } catch (e) {
      console.log(TAG, `createGroup Error: ${JSON.stringify(e)}`)
    }
  }

  startConnect() {
    if (this.selectDevice === null ) return
    let config:wifiManager.WifiP2PConfig = {
      deviceAddress: this.selectDevice.address,
      netId: -2,
      passphrase: this.connectPwd,
      groupName: "gp123",
      goBand: 0
    }
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
  build() {
    Column({space: 20}) {
      Text(this.title)
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