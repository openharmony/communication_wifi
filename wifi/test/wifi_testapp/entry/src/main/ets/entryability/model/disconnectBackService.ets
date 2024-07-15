import { common } from '@kit.AbilityKit';
import { promptAction } from '@kit.ArkUI';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { BusinessError } from '@kit.BasicServicesKit';

const TAG: string = '[Page_ServiceExtensionAbility]';
const DOMAIN_NUMBER: number = 0xFF00;

let connectionId: number;
@Entry
@Component
struct Page_ServiceExtensionAbility {
  build() {
    Column() {
      //...
      List({ initialIndex: 0 }) {
        ListItem() {
          Row() {
            //...
          }
          .onClick(() => {
            let context: common.UIAbilityContext = getContext(this) as common.UIAbilityContext; // UIAbilityContext
            // connectionId为调用connectServiceExtensionAbility接口时的返回值，需开发者自行维护
            context.disconnectServiceExtensionAbility(connectionId).then(() => {
              hilog.info(DOMAIN_NUMBER, TAG, 'disconnectServiceExtensionAbility success');
              // 成功断连后台服务
              promptAction.showToast({
                message: $r('app.string.SuccessfullyDisconnectBackendService')
              });
            }).catch((error: BusinessError) => {
              hilog.error(DOMAIN_NUMBER, TAG, 'disconnectServiceExtensionAbility failed');
            });
          })
        }
        //...
      }
      //...
    }
    //...
  }
}