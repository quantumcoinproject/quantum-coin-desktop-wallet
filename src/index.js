const {
    app,
    protocol,
    BrowserWindow,
    session,
    ipcMain,
    Menu,
    clipboard,
    shell
} = require("electron");

const path = require('path');
const sjcl = require('sjcl');
const fs = require('fs');
const readline = require('readline');
const { ethers } = require('ethers');
const { utils, BigNumber, message } = require('ethers');
const crypto = require('crypto');
const AES_ALGORITHM = 'aes-256-cbc';

const additionalData = { myKey: 'myValue' }
const gotTheLock = app.requestSingleInstanceLock(additionalData)
var startFilename = "index.html";
let currentWindow;

// Handle creating/removing shortcuts on Windows when installing/uninstalling.
if (require('electron-squirrel-startup')) {
  app.quit();
}

const createWindow = () => {
  // Create the browser window.
  const mainWindow = new BrowserWindow({
    width: 625,
      height: 800,
      webPreferences: {
          preload: path.join(__dirname, 'preload.js'),
          nodeIntegration: false,
          nodeIntegrationInWorker: false,
          nodeIntegrationInSubFrames: false,
          contextIsolation: true,
          enableRemoteModule: false,
      },
      autoHideMenuBar: true
  });

  currentWindow = mainWindow;

  // and load the index.html of the app.
    mainWindow.loadFile(path.join(__dirname, startFilename));

  // Open the DevTools.
  //mainWindow.webContents.openDevTools();

    if (process.platform == 'win32') {
        app.setAppUserModelId('Quantum Coin Wallet');
    }
};

if (!gotTheLock) {
    startFilename = 'instance.html';
} else {
    app.on('second-instance', (event, commandLine, workingDirectory, additionalData) => {
        // Someone tried to run a second instance, we should focus our window.
        if (currentWindow) {
            if (currentWindow.isMinimized()) {
                currentWindow.restore();
            }
            currentWindow.focus();
        }
    })
}

app.whenReady().then(() => {
    createWindow();
    
    app.on('activate', () => {
      // On OS X it's common to re-create a window in the app when the
      // dock icon is clicked and there are no other windows open.
      if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
      }
    });
})

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
//app.on('ready', createWindow);

// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});


ipcMain.handle('AppApiGetVersion', async (event, data) => {
    return app.getVersion();
})


// In this file you can include the rest of your app's specific main process
// code. You can also put them in separate files and import them here.
ipcMain.handle('ClipboardWriteText', async (event, data) => {
    clipboard.writeText(data);
})

// In this file you can include the rest of your app's specific main process
// code. You can also put them in separate files and import them here.
ipcMain.handle('OpenUrlInShell', async (event, data) => {
    shell.openExternal(data);
})

ipcMain.handle('FileApiReadFile', async (event, data) => {
    let filename = path.join(__dirname, data);

    if (fs == null || fs == undefined) {
        return null;
    }

    return fs.readFileSync(filename).toString();
})

ipcMain.handle('EthersApiPhraseToWallets', async (event, data) => {   
    const wallestList = [];
    const mnemonic = ethers.Mnemonic.fromPhrase(data);
    for (let index = 0; index < 100; index++) {
        const wallet = ethers.HDNodeWallet.fromMnemonic(mnemonic, `m/44'/60'/0'/0/${index}`);
        wallestList.push(wallet);
    }

    return wallestList;
})

ipcMain.handle('EthersApiPhraseToKeyPairs', async (event, data) => {
    const keyList = [];
    const mnemonic = ethers.Mnemonic.fromPhrase(data);
    for (let index = 0; index < 100; index++) {
        const wallet = ethers.HDNodeWallet.fromMnemonic(mnemonic, `m/44'/60'/0'/0/${index}`);
        const keyPair = {
            privateKey: wallet.privateKey,
            publicKey: wallet.publicKey
        }
        keyList.push(keyPair);
    }

    return keyList;
})

ipcMain.handle('EthersApiSignMessageWithPhrase', async (event, data) => {
    const mnemonic = ethers.Mnemonic.fromPhrase(data.phrase)
    const wallet = ethers.HDNodeWallet.fromMnemonic(mnemonic, `m/44'/60'/0'/0/${data.index}`);
    let sig = await wallet.signMessage(data.message);
    return sig;
})

ipcMain.handle('EthersApiWalletFromKey', async (event, data) => {
    let wallet = new ethers.Wallet(data);
    return wallet;
})

ipcMain.handle('EthersApiSignMessageWithKey', async (event, data) => {
    let wallet = new ethers.Wallet(data.key);
    let sig = await wallet.signMessage(data.message);
    return sig;
})

ipcMain.handle('EthersApiKeyStoreAccountFromJson', async (event, data) => {
    let keyStoreAccount = ethers.decryptKeystoreJsonSync(data.json, data.password);
    return keyStoreAccount;
})

ipcMain.handle('EthersApiVerify', async (event, data) => {
    try {
        const signerAddr = await ethers.verifyMessage(data.message, data.signature);
        if (signerAddr.toString().toLowerCase() !== data.address.toString().toLowerCase()) {
            return false;
        }
        return true;
    } catch (err) {
        return false;
    }
})

function base64ToBytes(base64) {
    const binString = atob(base64);
    return Uint8Array.from(binString, (m) => m.codePointAt(0));
}

function bytesToBase64(bytes) {
    const binString = Array.from(bytes, (byte) =>
        String.fromCodePoint(byte),
    ).join("");
    return btoa(binString);
}

ipcMain.handle('StorageApiGetPath', async (event, data) => {
    return require('electron').app.getPath('userData');
})

ipcMain.handle('CryptoApiEncrypt', async (event, data) => {
    const aesKey = base64ToBytes(data.key);
    const aesIV = base64ToBytes(data.iv);

    const cipher = crypto.createCipheriv(AES_ALGORITHM, aesKey, aesIV);
    let cipherText = cipher.update(data.plainText, 'utf8', 'base64');
    cipherText += cipher.final('base64');

    return cipherText;
})

ipcMain.handle('CryptoApiDecrypt', async (event, data) => {
    const aesKey = base64ToBytes(data.key);
    const aesIV = base64ToBytes(data.iv);

    const decipher = crypto.createDecipheriv(AES_ALGORITHM, aesKey, aesIV);
    let plainText = decipher.update(data.cipherText, 'base64', 'utf8');
    plainText += decipher.final();

    return plainText;
})

ipcMain.handle('CryptoApiScrypt', async (event, data) => {
    const salt = base64ToBytes(data.salt);

    return crypto.scryptSync(data.secret, salt, 32, { N: 16384, p: 1, r: 8 });
})

ipcMain.handle('FormatApiEtherToWei', async (event, data) => {
    const etherAmount = ethers.parseUnits(data, "ether")
    return etherAmount;
})

ipcMain.handle('FormatApiWeiToEther', async (event, data) => {
    const etherAmount = ethers.formatEther(data)
    return etherAmount;
})

ipcMain.handle('FormatApiWeiToEtherCommified', async (event, data) => {
    const etherAmount = ethers.formatEther(data)
    return etherAmount.toLocaleString();
})

ipcMain.handle('FormatApiIsValidEther', async (event, data) => {
    try {
        if (data.startsWith("0")) {
            return false;
        }
        const number = ethers.FixedNumber.fromString(data);
        let isNegative = number.isNegative();
        return !isNegative;
    }
    catch (error) {
        return false;
    }
})

ipcMain.handle('FormatApiCompareEther', async (event, data) => {
    try {
        const number1 = ethers.FixedNumber.fromString(data.num1.replaceAll(",",""));
        const number2 = ethers.FixedNumber.fromString(data.num2.replaceAll(",", ""));
        if (number1.isNegative() || number2.isNegative()) {
            throw new Error("error parsing numbers. negative values.");
        }

        if (number1.eq(number2)) {
            return 0;
        } else if (number1.gt(number2)) {
            return 1;
        } else {
            return -1;
        }
    }
    catch (error) {
        throw new Error("error parsing numbers");
    }
})
