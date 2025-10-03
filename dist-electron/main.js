"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const electron_1 = require("electron");
const node_path_1 = __importDefault(require("node:path"));
const isDev = process.env.VITE_DEV === "1";
async function createWindow() {
    const win = new electron_1.BrowserWindow({
        width: 1200,
        height: 800,
        webPreferences: {
            preload: node_path_1.default.join(__dirname, "preload.js"),
            contextIsolation: true
        }
    });
    if (isDev) {
        await win.loadURL("http://localhost:5173");
        win.webContents.openDevTools({ mode: "detach" });
    }
    else {
        const indexHtml = node_path_1.default.resolve(__dirname, "../web/index.html");
        await win.loadFile(indexHtml);
    }
}
electron_1.app.whenReady().then(createWindow);
electron_1.app.on("window-all-closed", () => { if (process.platform !== "darwin")
    electron_1.app.quit(); });
