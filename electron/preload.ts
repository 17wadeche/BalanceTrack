import { contextBridge } from "electron";
contextBridge.exposeInMainWorld("__BALANCETRACK__", {
  ping: () => "pong"
});
