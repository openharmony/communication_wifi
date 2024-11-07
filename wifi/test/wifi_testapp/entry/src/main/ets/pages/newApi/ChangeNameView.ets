import { NormalNav } from "./Components/NormalNav"
import { wifiManager } from "@kit.ConnectivityKit"

@Component
export struct ChangeNameView {

  @Consume('p2pPathInfo') pathInfo: NavPathStack
  @State device: null | wifiManager.WifiP2pDevice = null
  @State deviceStr: string = ''

  async aboutToAppear() {
    this.device =  await wifiManager.getP2pLocalDevice()
    this.deviceStr = this.device.deviceName
  }

  build() {
    NavDestination() {
      Column() {
        NormalNav({title: '设备名称'})
        TextInput({text: $$this.deviceStr})
        Text('使用蓝牙互联，WLAN直连，热点共享和USB连接时，其他设备将看到此名称')
        Blank()
          .layoutWeight(1)
        Row() {
          Button('取消')
            .onClick(() => {
              this.pathInfo.pop()
            })
          Button('确定')
            .onClick(() => {
              if (this.deviceStr.length > 0) {
                wifiManager.setDeviceName(this.deviceStr)
                this.pathInfo.pop(null, true)
              }
            })
        }
      }
    }
    .hideTitleBar(true)
  }

}