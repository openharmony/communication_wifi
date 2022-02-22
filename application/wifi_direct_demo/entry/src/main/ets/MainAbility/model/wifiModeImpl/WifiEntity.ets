export class WifiEntity {
  index: number
  deviceName: string
  macAddress: string
  status: number

  constructor(index: number, deviceName: string, macAddress: string, status: number) {
    this.index = index
    this.deviceName = deviceName
    this.macAddress = macAddress
    this.status = status
  }
}