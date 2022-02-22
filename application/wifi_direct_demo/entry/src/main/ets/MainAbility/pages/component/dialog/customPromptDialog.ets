/**
 * 自定义提示弹窗
 */
@CustomDialog
export default struct CustomPromptDialog {
  title: string = '提示';
  cancelVal: string= '取消';
  confirmVal: string= '确定';
  @State contentVal: string = '';
  controller: CustomDialogController;
  eventAction: () => void;

  build() {
    Column() {
      Text(this.title)
        .width('95%')
        .fontSize(20)
        .fontColor(Color.Black)
        .fontWeight(FontWeight.Bold)
        .margin({
          top: 20,
          bottom: 15,
          left: 20
        })
      Scroll() {
        Flex() {
          Text(this.contentVal)
            .fontSize(18)
            .fontColor(Color.Black)
            .lineHeight(33)
        }
        .margin({
          left: 20,
          top: 10,
          right: 20,
          bottom: 10
        })
      }
      .width('95%')
      .height(120)
      .scrollable(ScrollDirection.Vertical)

      Row() {
        Button(this.cancelVal, { type: ButtonType.Capsule, stateEffect: true })
          .padding({
            top: 10,
            bottom: 10
          })
          .stateEffect(false)
          .fontSize(17)
          .fontColor(Color.Black)
          .backgroundColor(Color.White)
          .layoutWeight(1)
          .onClick(() => {
            this.controller.close();
          })
        Divider()
          .width(1)
          .height(30)
          .color('#bcbcbc')
          .vertical(true)
        Button(this.confirmVal, { type: ButtonType.Capsule, stateEffect: true })
          .padding({
            top: 10,
            bottom: 10
          })
          .stateEffect(false)
          .fontSize(17)
          .fontColor(Color.Black)
          .backgroundColor(Color.White)
          .layoutWeight(1)
          .onClick(() => {
            this.controller.close();
            this.eventAction();
          })
      }
    }
    .width('100%')
    .backgroundColor(Color.White)
    .borderRadius(15)
  }
}