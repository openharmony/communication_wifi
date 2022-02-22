import BaseModel from '../model/BaseModel.ets';

export class LogUtil extends BaseModel {
  TAG() {
    return '------------ P2P ------------ ';
  }

  debug(msg) {
    console.info(this.TAG() + msg);
  }

  log(msg) {
    console.log(this.TAG() + msg);

  }

  info(msg) {
    console.info(this.TAG() + msg);
  }

  warn(msg) {
    console.warn(this.TAG() + msg);
  }

  error(msg) {
    console.error(this.TAG() + msg);
  }
}

let mLogUtil = new LogUtil();

export default mLogUtil as LogUtil;

