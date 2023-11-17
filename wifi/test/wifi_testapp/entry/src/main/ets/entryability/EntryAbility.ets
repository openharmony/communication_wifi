import UIAbility from '@ohos.app.ability.UIAbility';
import hilog from '@ohos.hilog';
import window from '@ohos.window';
import { GlobalThis } from "../utils/globalThis"
import abilityAccessCtrl from '@ohos.abilityAccessCtrl'

export default class EntryAbility extends UIAbility {
  onCreate( want , launchParam ) {
    hilog.info( 0x0000 , 'testTag' , '%{public}s' , 'Ability onCreate' );
    GlobalThis.getInstance().setContext( 'context' , this.context )
    //        this.context.request
    //        abilityAccessCtrl.createAtManager().requestPermissionsFromUser(this.context, [])
  }

  onDestroy() {
    hilog.info( 0x0000 , 'testTag' , '%{public}s' , 'Ability onDestroy' );
  }

  onWindowStageCreate( windowStage: window.WindowStage ) {
    // Main window is created, set main page for this ability
    hilog.info( 0x0000 , 'testTag' , '%{public}s' , 'Ability onWindowStageCreate' );

    windowStage.loadContent( 'pages/homePage' , ( err , data ) => {
      if ( err.code ) {
        hilog.error( 0x0000 , 'testTag' , 'Failed to load the content. Cause: %{public}s' , JSON.stringify( err ) ?? '' );
        return;
      }
      hilog.info( 0x0000 , 'testTag' , 'Succeeded in loading the content. Data: %{public}s' , JSON.stringify( data ) ?? '' );
    } );

    let context = this.context;
    let pathDir = context.filesDir;
    AppStorage.setOrCreate( "pathDir" , pathDir )
  }

  onWindowStageDestroy() {
    // Main window is destroyed, release UI related resources
    hilog.info( 0x0000 , 'testTag' , '%{public}s' , 'Ability onWindowStageDestroy' );
  }

  onForeground() {
    // Ability has brought to foreground
    hilog.info( 0x0000 , 'testTag' , '%{public}s' , 'Ability onForeground' );
  }

  onBackground() {
    // Ability has back to background
    hilog.info( 0x0000 , 'testTag' , '%{public}s' , 'Ability onBackground' );
  }
}
