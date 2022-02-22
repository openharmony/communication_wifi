/******/ (() => { // webpackBootstrap
var __webpack_exports__ = {};
/*!***********************************************************************************************!*\
  !*** ../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/pages/second.ets?entry ***!
  \***********************************************************************************************/
var router = globalThis.requireNativeModule('system.router');
class Second extends View {
    constructor(compilerAssignedUniqueChildId, parent, params) {
        super(compilerAssignedUniqueChildId, parent);
        this.content = "Second Page";
        this.updateWithValueParams(params);
    }
    updateWithValueParams(params) {
        if (params.content !== undefined) {
            this.content = params.content;
        }
    }
    aboutToBeDeleted() {
        SubscriberManager.Get().delete(this.id());
    }
    render() {
        Flex.create({ direction: FlexDirection.Column, alignItems: ItemAlign.Center, justifyContent: FlexAlign.Center });
        Flex.debugLine("pages/second.ets(9:5)");
        Flex.width('100%');
        Flex.height('100%');
        Text.create(`${this.content}`);
        Text.debugLine("pages/second.ets(10:7)");
        Text.fontSize(50);
        Text.fontWeight(FontWeight.Bold);
        Text.pop();
        Button.createWithChild();
        Button.debugLine("pages/second.ets(13:7)");
        Button.type(ButtonType.Capsule);
        Button.margin({
            top: 20
        });
        Button.backgroundColor('#0D9FFB');
        Button.onClick(() => {
            router.back();
        });
        Text.create('back to index');
        Text.debugLine("pages/second.ets(14:9)");
        Text.fontSize(20);
        Text.fontWeight(FontWeight.Bold);
        Text.pop();
        Button.pop();
        Flex.pop();
    }
}
loadDocument(new Second("1", undefined, {}));

/******/ })()
;