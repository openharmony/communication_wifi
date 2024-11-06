@Component
export struct NormalNav {
  title: string = ''

  build() {
    Row() {
      Text(this.title)
        .margin({ left: 20 })
    }
    .height(50)
  }
}