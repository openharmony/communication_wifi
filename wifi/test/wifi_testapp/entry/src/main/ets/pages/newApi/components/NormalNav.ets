@Component
export struct NormalNav {
  @Require @Prop title: Resource | string

  build() {
    Row() {
      Text(this.title)
        .margin({ left: 20 })
    }
    .height(50)
  }
}