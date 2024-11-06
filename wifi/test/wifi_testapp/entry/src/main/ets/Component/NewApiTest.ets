import { TestData } from "../entryability/model/testData"
import { AllInOneView } from "../pages/newApi/AllInOneView"
import { TestList } from "./testList"

@Component
export struct NewApiTest {
  @Provide('newApiPathStack') pathStack: NavPathStack = new NavPathStack()
  private testItems!: TestData[]

  build() {
    Column() {
      TestList({
        testItems : this.testItems
      })
    }
  }

  @Builder routeMap(name: string) {
    if (name === 'allInOne') {
      AllInOneView()
    }

  }
}