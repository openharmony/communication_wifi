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
        Row() {
          TextInput({text: $$this.deviceStr})
        }.padding({left: 20, right: 20})
        Text('使用蓝牙互联，WLAN直连，热点共享和USB连接时，其他设备将看到此名称')
          .margin({ top: 20, left: 20, right: 20 })
        Blank()
          .layoutWeight(1)
        Row({space: 40 }) {
          Button('取消')
            .onClick(() => {
              this.pathInfo.pop()
            })
            .normalButtonStyle()
          Button('确定')
            .onClick(() => {
              if (this.deviceStr.length > 0) {
                wifiManager.setDeviceName(this.deviceStr)
                this.pathInfo.pop(null, true)
              }
            })
            .normalButtonStyle()
        }
        .margin({ bottom: 45 })
      }
    }
    .hideTitleBar(true)
  }
}

@Extend(Button)
function normalButtonStyle() {
  .width(150)
  .height(40)
  .backgroundColor('#F2F2F2')
  .fontColor(Color.Blue)
}