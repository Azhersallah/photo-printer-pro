const { app, BrowserWindow, ipcMain, dialog, screen, Menu } = require('electron');
const path = require('path');
const fs = require('fs');
const { execSync } = require('child_process');
const crypto = require('crypto');
const https = require('https');

// Enable SharedArrayBuffer for WASM threading
app.commandLine.appendSwitch('enable-features', 'SharedArrayBuffer');

const isDev = !require('electron').app.isPackaged;
let mainWindow;
let fileToOpen = null;

// ============================================
// APP SETTINGS - JSON FILE
// ============================================

const SETTINGS_FILE_NAME = 'settings.json';

function getSettingsFilePath() {
  const userDataPath = app.getPath('userData');
  return path.join(userDataPath, SETTINGS_FILE_NAME);
}

function loadSettings() {
  try {
    const settingsPath = getSettingsFilePath();
    if (fs.existsSync(settingsPath)) {
      const data = fs.readFileSync(settingsPath, 'utf8');
      return JSON.parse(data);
    }
  } catch (err) {
    console.error('Failed to load settings:', err);
  }
  return null;
}

function saveSettings(settings) {
  try {
    const settingsPath = getSettingsFilePath();
    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2), 'utf8');
    return true;
  } catch (err) {
    console.error('Failed to save settings:', err);
    return false;
  }
}

// ============================================
// SECURE LICENSE SYSTEM - DURABLE OBJECTS + WEBSOCKET
// ============================================

const LICENSE_API_URL = 'https://pppro-api.azhersallah1.workers.dev';
const LICENSE_WS_URL = 'wss://pppro-api.azhersallah1.workers.dev/ws';
const LICENSE_FILE_NAME = 'license.dat';

// WebSocket connection for real-time status
let wsConnection = null;
let wsReconnectTimer = null;
const WS_RECONNECT_DELAY = 5000;

// Get license file path
function getLicenseFilePath() {
  const userDataPath = app.getPath('userData');
  return path.join(userDataPath, LICENSE_FILE_NAME);
}

// Generate checksum for integrity
function generateChecksum(data, machineId) {
  const content = `${data.token}:${data.machineId}:${data.activatedAt}:${data.lastVerified}:${machineId}`;
  return crypto.createHash('sha256').update(content).digest('hex').substring(0, 16);
}

// Encrypt license data (hardware-bound)
function encryptLicenseData(data, machineId) {
  const key = crypto.scryptSync(machineId + 'PPro-License-2024', 'license-salt', 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

// Decrypt license data
function decryptLicenseData(encryptedData, machineId) {
  try {
    const parts = encryptedData.split(':');
    if (parts.length !== 2) return null;

    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const key = crypto.scryptSync(machineId + 'PPro-License-2024', 'license-salt', 32);
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
  } catch {
    return null;
  }
}

// Save license to encrypted file
function saveLicenseToFile(token, machineId) {
  try {
    const now = new Date().toISOString();
    const licenseData = { token, machineId, activatedAt: now, lastVerified: now };
    const checksum = generateChecksum(licenseData, machineId);
    const fullData = { ...licenseData, checksum };
    const encrypted = encryptLicenseData(fullData, machineId);
    fs.writeFileSync(getLicenseFilePath(), encrypted, 'utf8');
    return true;
  } catch (err) {
    console.error('Failed to save license:', err);
    return false;
  }
}

// Load license from file
function loadLicenseFromFile(machineId) {
  try {
    const licensePath = getLicenseFilePath();
    if (!fs.existsSync(licensePath)) return null;
    
    const encrypted = fs.readFileSync(licensePath, 'utf8');
    const data = decryptLicenseData(encrypted, machineId);
    if (!data) return null;
    
    // Verify checksum
    const { checksum, ...rest } = data;
    const expectedChecksum = generateChecksum(rest, machineId);
    if (checksum !== expectedChecksum) {
      console.error('License checksum mismatch');
      return null;
    }
    
    // Verify machine ID
    if (data.machineId !== machineId) {
      console.error('License machine ID mismatch');
      return null;
    }
    
    return data;
  } catch (err) {
    console.error('Failed to load license:', err);
    return null;
  }
}

// Delete license file
function deleteLicenseFile() {
  try {
    const licensePath = getLicenseFilePath();
    if (fs.existsSync(licensePath)) fs.unlinkSync(licensePath);
    return true;
  } catch { return false; }
}

// Validate token structure (no expiration - works forever after activation)
function isTokenValid(token) {
  try {
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const parts = decoded.split(':');
    // Token format: version:machineId:timestamp:signature
    return parts.length >= 4;
  } catch { return false; }
}

// API call helper
function apiCall(action, machineId, token = null, appVersion = null) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({ action, machineId, token, appVersion });
    const url = new URL(LICENSE_API_URL);
    
    const options = {
      hostname: url.hostname,
      port: 443,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      },
      timeout: 15000
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode === 200) resolve(JSON.parse(data));
          else reject(new Error(`API error: ${res.statusCode}`));
        } catch (e) { reject(e); }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.write(postData);
    req.end();
  });
}

// Main license check function
async function checkLicenseSecure(machineId) {
  if (!machineId) {
    return { activated: false, source: 'offline', error: 'No machine ID' };
  }

  const storedLicense = loadLicenseFromFile(machineId);
  const appVersion = app.getVersion();

  // Try online verification
  try {
    if (storedLicense && storedLicense.token) {
      // Have existing token - try to refresh
      const result = await apiCall('refresh', machineId, storedLicense.token, appVersion);
      
      if (result.revoked) {
        deleteLicenseFile();
        return { activated: false, source: 'online', error: 'License revoked' };
      }
      
      if (result.activated && result.token) {
        saveLicenseToFile(result.token, machineId);
        return { activated: true, source: 'online', machineId };
      }
    } else {
      // First activation - must be online
      const result = await apiCall('verify', machineId, null, appVersion);
      
      if (result.activated && result.token) {
        saveLicenseToFile(result.token, machineId);
        return { activated: true, source: 'online', machineId };
      }
      
      return { activated: false, source: 'online', machineId };
    }
  } catch (err) {
    console.log('Online verification failed:', err.message);
  }

  // Offline fallback - works forever after first activation
  if (storedLicense && storedLicense.token) {
    if (isTokenValid(storedLicense.token)) {
      return { activated: true, source: 'offline', machineId };
    }
    // Invalid token structure
    deleteLicenseFile();
    return { activated: false, source: 'offline', error: 'Invalid license', machineId };
  }

  return { activated: false, source: 'offline', error: 'Internet required for first activation', machineId };
}

// ============================================
// HARDWARE MACHINE ID
// ============================================

function getHardwareMachineId() {
  try {
    let machineId = '';
    
    if (process.platform === 'win32') {
      try {
        const mbSerial = execSync('powershell -command "(Get-WmiObject Win32_BaseBoard).SerialNumber"', { encoding: 'utf8', windowsHide: true });
        const mbMatch = mbSerial.trim();
        if (mbMatch && mbMatch !== 'To be filled by O.E.M.' && mbMatch !== 'Default string' && mbMatch.length > 3) {
          machineId = mbMatch;
        }
      } catch (e) {
        try {
          const mbSerial = execSync('wmic baseboard get serialnumber', { encoding: 'utf8' });
          const mbMatch = mbSerial.split('\n')[1]?.trim();
          if (mbMatch && mbMatch !== 'To be filled by O.E.M.' && mbMatch.length > 3) {
            machineId = mbMatch;
          }
        } catch (e2) {}
      }
      
      if (!machineId) {
        try {
          const biosSerial = execSync('powershell -command "(Get-WmiObject Win32_BIOS).SerialNumber"', { encoding: 'utf8', windowsHide: true });
          const biosMatch = biosSerial.trim();
          if (biosMatch && biosMatch !== 'To be filled by O.E.M.' && biosMatch !== 'Default string' && biosMatch.length > 3) {
            machineId = biosMatch;
          }
        } catch (e) {}
      }
      
      if (!machineId) {
        try {
          const cpuId = execSync('powershell -command "(Get-WmiObject Win32_Processor).ProcessorId"', { encoding: 'utf8', windowsHide: true });
          const cpuMatch = cpuId.trim();
          if (cpuMatch && cpuMatch.length > 3) machineId = cpuMatch;
        } catch (e) {}
      }
      
      if (!machineId) {
        try {
          const regResult = execSync('powershell -command "(Get-ItemProperty -Path \'HKLM:\\SOFTWARE\\Microsoft\\Cryptography\' -Name MachineGuid).MachineGuid"', { encoding: 'utf8', windowsHide: true });
          machineId = regResult.trim();
        } catch (e) {}
      }
    } else if (process.platform === 'darwin') {
      try {
        const result = execSync('system_profiler SPHardwareDataType | grep "Hardware UUID"', { encoding: 'utf8' });
        machineId = result.split(':')[1]?.trim() || '';
      } catch (e) {}
    } else {
      try {
        if (fs.existsSync('/sys/class/dmi/id/product_uuid')) {
          machineId = fs.readFileSync('/sys/class/dmi/id/product_uuid', 'utf8').trim();
        } else if (fs.existsSync('/etc/machine-id')) {
          machineId = fs.readFileSync('/etc/machine-id', 'utf8').trim();
        }
      } catch (e) {}
    }
    
    if (machineId) {
      machineId = machineId.replace(/\//g, '_').replace(/^[_\-\.]+/, '').replace(/[_\-\.]+$/, '').replace(/\s+/g, '');
    }
    
    return machineId || null;
  } catch (err) {
    console.error('Failed to get hardware machine ID:', err);
    return null;
  }
}

// ============================================
// WINDOW CREATION
// ============================================

function createWindow() {
  const { width: screenWidth, height: screenHeight } = screen.getPrimaryDisplay().workAreaSize;
  const windowWidth = Math.round(screenWidth * 0.9);
  const windowHeight = Math.round(screenHeight * 0.9);

  Menu.setApplicationMenu(null);

  const iconPath = isDev 
    ? path.join(__dirname, 'build', 'icon.png')
    : path.join(process.resourcesPath, 'build', 'icon.png');

  mainWindow = new BrowserWindow({
    width: windowWidth,
    height: windowHeight,
    frame: true,
    center: true,
    icon: iconPath,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      devTools: false, // Disabled
    },
  });

  // Block DevTools shortcuts in production
  if (!isDev) {
    mainWindow.webContents.on('before-input-event', (event, input) => {
      if (input.key === 'F12') event.preventDefault();
      if (input.control && input.shift && input.key.toLowerCase() === 'i') event.preventDefault();
      if (input.control && input.shift && input.key.toLowerCase() === 'j') event.preventDefault();
      if (input.control && input.key.toLowerCase() === 'u') event.preventDefault();
    });
  }

  if (isDev) {
    mainWindow.loadURL('http://localhost:3000');
  } else {
    mainWindow.loadFile(path.join(__dirname, 'dist', 'index.html'));
  }

  mainWindow.maximize();
  mainWindow.on('closed', () => { mainWindow = null; });

  mainWindow.webContents.on('did-finish-load', () => {
    mainWindow.webContents.setZoomFactor(1.0);
    if (fileToOpen) {
      pendingFileToOpen = fileToOpen;
      fileToOpen = null;
      setTimeout(() => {
        if (pendingFileToOpen) {
          openProjectFile(pendingFileToOpen);
          pendingFileToOpen = null;
        }
      }, 1000);
    }
  });

  mainWindow.webContents.on('before-input-event', (event, input) => {
    if (input.control && (input.key === '+' || input.key === '-' || input.key === '=' || input.key === '0')) {
      event.preventDefault();
    }
  });
}

// ============================================
// LICENSE STATE - CONTROLS ALL FEATURES
// ============================================

let isLicenseValid = false;
let cachedMachineId = null;
let heartbeatInterval = null;
let updateCheckInterval = null;
let lastKnownActivationState = null;
let lastNotifiedUpdateVersion = null;

// Heartbeat with activity detection - REMOVED (using WebSocket now)
// WebSocket connection = online, disconnect = offline
// Durable Objects handles connection persistence automatically

// Connect WebSocket for real-time online status
function connectWebSocket(machineId) {
  if (wsConnection && wsConnection.readyState === 1) return; // Already connected
  
  try {
    const WebSocket = require('ws');
    const wsUrl = `${LICENSE_WS_URL}?machineId=${encodeURIComponent(machineId)}&type=desktop`;
    
    wsConnection = new WebSocket(wsUrl);
    
    wsConnection.on('open', () => {
      console.log('WebSocket connected - online status active');
      if (wsReconnectTimer) {
        clearTimeout(wsReconnectTimer);
        wsReconnectTimer = null;
      }
    });
    
    wsConnection.on('message', (data) => {
      try {
        const msg = JSON.parse(data.toString());
        
        // Handle license status changes from server
        if (msg.type === 'license-activated') {
          isLicenseValid = true;
          lastKnownActivationState = true;
          if (mainWindow && mainWindow.webContents) {
            mainWindow.webContents.send('license-activated');
          }
        } else if (msg.type === 'license-revoked') {
          isLicenseValid = false;
          lastKnownActivationState = false;
          deleteLicenseFile();
          if (mainWindow && mainWindow.webContents) {
            mainWindow.webContents.send('license-revoked');
          }
        }
      } catch (e) {
        console.log('WebSocket message parse error:', e);
      }
    });
    
    wsConnection.on('close', () => {
      console.log('WebSocket disconnected');
      wsConnection = null;
      // Reconnect after delay
      if (!wsReconnectTimer) {
        wsReconnectTimer = setTimeout(() => {
          wsReconnectTimer = null;
          if (cachedMachineId) connectWebSocket(cachedMachineId);
        }, WS_RECONNECT_DELAY);
      }
    });
    
    wsConnection.on('error', (err) => {
      console.log('WebSocket error:', err.message);
    });
    
  } catch (err) {
    console.log('WebSocket connection failed:', err.message);
  }
}

// Disconnect WebSocket
function disconnectWebSocket() {
  if (wsReconnectTimer) {
    clearTimeout(wsReconnectTimer);
    wsReconnectTimer = null;
  }
  if (wsConnection) {
    wsConnection.close();
    wsConnection = null;
  }
}

// Quick license check (uses cached state)
function requireLicense() {
  if (!isLicenseValid) {
    return { success: false, error: 'LICENSE_REQUIRED', message: 'بەرنامە چالاک نەکراوە' };
  }
  return { success: true };
}

// Start WebSocket connection
function startHeartbeat() {
  if (heartbeatInterval) clearInterval(heartbeatInterval);
  if (updateCheckInterval) clearInterval(updateCheckInterval);
  
  // Connect WebSocket for real-time online status
  if (cachedMachineId) {
    connectWebSocket(cachedMachineId);
  }
  
  // Check for app updates every 30 seconds
  checkForAppUpdate();
  updateCheckInterval = setInterval(checkForAppUpdate, 30000);
}

// Check for app updates from GitHub
async function checkForAppUpdate() {
  if (!mainWindow || !mainWindow.webContents) return;
  
  try {
    const release = await fetchLatestRelease();
    if (!release || !release.tag_name) return;
    
    const latestVersion = release.tag_name.replace('v', '');
    const currentVersion = app.getVersion();
    const isNewer = latestVersion.localeCompare(currentVersion, undefined, { numeric: true }) > 0;
    
    if (isNewer && latestVersion !== lastNotifiedUpdateVersion) {
      lastNotifiedUpdateVersion = latestVersion;
      console.log('New update available:', latestVersion);
      
      mainWindow.webContents.send('server-update-notification', {
        title: 'نوێکردنەوەی نوێ',
        message: `وەشانی ${latestVersion} بەردەستە. تکایە بەرنامەکە نوێ بکەرەوە.`,
        version: latestVersion,
        forceUpdate: false
      });
      
      mainWindow.webContents.send('update-status', {
        status: 'available',
        message: `نوێکردنەوەی نوێ بەردەستە: ${latestVersion}`,
        messageEn: `New update available: ${latestVersion}`,
        version: latestVersion
      });
      
      latestReleaseInfo = release;
    }
  } catch (err) {
    // Silent fail
  }
}

// Stop WebSocket and mark offline
async function stopHeartbeat() {
  if (heartbeatInterval) {
    clearInterval(heartbeatInterval);
    heartbeatInterval = null;
  }
  if (updateCheckInterval) {
    clearInterval(updateCheckInterval);
    updateCheckInterval = null;
  }
  
  // Disconnect WebSocket (server will mark as offline automatically)
  disconnectWebSocket();
}

// ============================================
// IPC HANDLERS
// ============================================

// Window controls
ipcMain.on('window-minimize', () => { if (mainWindow) mainWindow.minimize(); });
ipcMain.on('window-maximize', () => {
  if (mainWindow) {
    if (mainWindow.isMaximized()) mainWindow.unmaximize();
    else mainWindow.maximize();
  }
});
ipcMain.on('window-close', () => { if (mainWindow) mainWindow.close(); });
ipcMain.handle('window-is-maximized', () => mainWindow ? mainWindow.isMaximized() : false);
ipcMain.handle('get-machine-id', () => getHardwareMachineId());
ipcMain.handle('get-app-version', () => app.getVersion());

// Settings handlers - JSON file
ipcMain.handle('load-settings', () => loadSettings());
ipcMain.handle('save-settings', (event, settings) => saveSettings(settings));

// User activity tracking (scroll, click, keypress, mouse move)
// Note: Activity tracking now handled via WebSocket connection
ipcMain.on('user-activity', () => {
  // WebSocket connection handles online status automatically
});

// SECURE LICENSE CHECK
ipcMain.handle('check-license', async () => {
  const machineId = getHardwareMachineId();
  cachedMachineId = machineId;
  
  if (!machineId) {
    isLicenseValid = false;
    return { activated: false, machineId: null, error: 'Could not get machine ID' };
  }
  
  // ASAR integrity check
  if (app.isPackaged) {
    const asarPath = path.join(process.resourcesPath, 'app.asar');
    const extractedPath = path.join(process.resourcesPath, 'app');
    
    if (fs.existsSync(extractedPath) || !fs.existsSync(asarPath)) {
      isLicenseValid = false;
      dialog.showMessageBoxSync({
        type: 'error',
        title: 'Error',
        message: 'Application files corrupted. Please reinstall.',
        buttons: ['OK']
      });
      app.quit();
      return { activated: false, machineId, error: 'Integrity check failed' };
    }
  }
  
  // Use secure license check
  const result = await checkLicenseSecure(machineId);
  isLicenseValid = result.activated;
  lastKnownActivationState = result.activated;
  
  // Always start heartbeat (for tracking and live status updates)
  startHeartbeat();
  
  return result;
});

// Project file handling - ALL REQUIRE LICENSE
let currentProjectPath = null;
let pendingFileToOpen = null;

ipcMain.handle('save-project', async (event, { content, filePath }) => {
  const licenseCheck = requireLicense();
  if (!licenseCheck.success) return licenseCheck;
  
  try {
    // Use async write for large files
    await fs.promises.writeFile(filePath, content, 'utf-8');
    currentProjectPath = filePath;
    return { success: true, filePath };
  } catch (err) {
    console.error('Save project error:', err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle('save-project-as', async (event, { content, defaultName }) => {
  const licenseCheck = requireLicense();
  if (!licenseCheck.success) return licenseCheck;
  
  try {
    const result = await dialog.showSaveDialog(mainWindow, {
      title: 'Save Project As',
      defaultPath: defaultName || 'project.pppro',
      filters: [{ name: 'Photo Printer Pro Project', extensions: ['pppro'] }]
    });
    
    if (result.canceled || !result.filePath) return { success: false, canceled: true };
    
    // Use async write for large files
    await fs.promises.writeFile(result.filePath, content, 'utf-8');
    currentProjectPath = result.filePath;
    return { success: true, filePath: result.filePath };
  } catch (err) {
    console.error('Save project as error:', err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle('get-current-project-path', () => currentProjectPath);
ipcMain.handle('set-current-project-path', (event, filePath) => { currentProjectPath = filePath; return true; });
ipcMain.handle('set-window-title', (event, title) => { if (mainWindow) mainWindow.setTitle(title); return true; });

ipcMain.handle('open-project-dialog', async () => {
  const licenseCheck = requireLicense();
  if (!licenseCheck.success) return licenseCheck;
  
  try {
    const result = await dialog.showOpenDialog(mainWindow, {
      title: 'Open Project',
      filters: [{ name: 'Photo Printer Pro Project', extensions: ['pppro'] }],
      properties: ['openFile']
    });
    
    if (result.canceled || !result.filePaths || result.filePaths.length === 0) {
      return { success: false, canceled: true };
    }
    
    const filePath = result.filePaths[0];
    const content = fs.readFileSync(filePath, 'utf-8');
    currentProjectPath = filePath;
    return { success: true, content, filePath };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('get-pending-file', () => {
  // Allow pending file only if licensed
  if (!isLicenseValid) return { success: false, noPendingFile: true };
  
  if (pendingFileToOpen && fs.existsSync(pendingFileToOpen)) {
    try {
      const content = fs.readFileSync(pendingFileToOpen, 'utf-8');
      const filePath = pendingFileToOpen;
      currentProjectPath = filePath;
      pendingFileToOpen = null;
      return { success: true, content, filePath };
    } catch (err) {
      pendingFileToOpen = null;
      return { success: false, error: err.message };
    }
  }
  return { success: false, noPendingFile: true };
});

function openProjectFile(filePath) {
  if (!isLicenseValid) return; // Block if not licensed
  if (!filePath || !fs.existsSync(filePath)) return;
  try {
    const encryptedContent = fs.readFileSync(filePath, 'utf-8');
    currentProjectPath = filePath;
    if (mainWindow) {
      mainWindow.webContents.send('open-project-encrypted', { content: encryptedContent, filePath });
    }
  } catch (err) {
    console.error('Failed to read project file', err);
  }
}

// ============================================
// AUTO UPDATER
// ============================================

const GITHUB_OWNER = 'Azhersallah';
const GITHUB_REPO = 'photo-printer-pro';
let latestReleaseInfo = null;
let downloadedFilePath = null;

function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

async function fetchLatestRelease() {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.github.com',
      path: `/repos/${GITHUB_OWNER}/${GITHUB_REPO}/releases/latest`,
      method: 'GET',
      headers: { 'User-Agent': 'Photo-Printer-Pro-Updater', 'Accept': 'application/vnd.github.v3+json' }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode === 200) resolve(JSON.parse(data));
          else reject(new Error(`GitHub API error: ${res.statusCode}`));
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function downloadAsset(assetId, assetName, totalSize) {
  return new Promise((resolve, reject) => {
    const tempDir = app.getPath('temp');
    const filePath = path.join(tempDir, assetName);
    const file = fs.createWriteStream(filePath, { highWaterMark: 1024 * 1024 });
    
    let downloadedBytes = 0;
    let lastProgressUpdate = 0;
    let lastBytes = 0;
    let lastTime = Date.now();
    let speed = 0;

    const options = {
      hostname: 'api.github.com',
      path: `/repos/${GITHUB_OWNER}/${GITHUB_REPO}/releases/assets/${assetId}`,
      method: 'GET',
      headers: { 'User-Agent': 'Photo-Printer-Pro-Updater', 'Accept': 'application/octet-stream' }
    };

    const makeRequest = (opts) => {
      const req = https.request(opts, (res) => {
        if (res.statusCode === 302 || res.statusCode === 301) {
          const redirectUrl = new URL(res.headers.location);
          makeRequest({
            hostname: redirectUrl.hostname,
            path: redirectUrl.pathname + redirectUrl.search,
            method: 'GET', port: 443,
            headers: { 'User-Agent': 'Photo-Printer-Pro-Updater', 'Connection': 'keep-alive' }
          });
          return;
        }

        if (res.statusCode !== 200) { reject(new Error(`Download failed: ${res.statusCode}`)); return; }

        res.pipe(file);
        res.on('data', (chunk) => {
          downloadedBytes += chunk.length;
          const now = Date.now();
          if (now - lastProgressUpdate > 200) {
            const timeDiff = (now - lastTime) / 1000;
            const bytesDiff = downloadedBytes - lastBytes;
            speed = timeDiff > 0 ? bytesDiff / timeDiff : 0;
            lastTime = now; lastBytes = downloadedBytes; lastProgressUpdate = now;
            const percent = Math.round((downloadedBytes / totalSize) * 100);
            
            if (mainWindow && mainWindow.webContents) {
              mainWindow.webContents.send('update-status', {
                status: 'downloading', message: `داگرتن... ${percent}%`, messageEn: `Downloading... ${percent}%`,
                percent, transferred: formatBytes(downloadedBytes), total: formatBytes(totalSize), speed: formatBytes(speed) + '/s'
              });
            }
          }
        });
        res.on('end', () => file.end(() => resolve(filePath)));
        res.on('error', (err) => { file.close(); fs.unlink(filePath, () => {}); reject(err); });
      });
      req.setTimeout(300000);
      req.on('error', (err) => { file.close(); fs.unlink(filePath, () => {}); reject(err); });
      req.end();
    };
    makeRequest(options);
  });
}

ipcMain.handle('check-for-updates', async () => {
  try {
    if (mainWindow && mainWindow.webContents) {
      mainWindow.webContents.send('update-status', { status: 'checking', message: 'گەڕان بۆ نوێکردنەوە...', messageEn: 'Checking for updates...' });
    }

    const release = await fetchLatestRelease();
    latestReleaseInfo = release;
    
    const latestVersion = release.tag_name.replace('v', '');
    const currentVersion = app.getVersion();
    const isNewer = latestVersion.localeCompare(currentVersion, undefined, { numeric: true }) > 0;
    
    if (isNewer) {
      if (mainWindow && mainWindow.webContents) {
        mainWindow.webContents.send('update-status', {
          status: 'available', message: `نوێکردنەوەی نوێ بەردەستە: ${latestVersion}`,
          messageEn: `New update available: ${latestVersion}`, version: latestVersion
        });
      }
      return { success: true, updateAvailable: true, version: latestVersion };
    } else {
      if (mainWindow && mainWindow.webContents) {
        mainWindow.webContents.send('update-status', { status: 'not-available', message: 'هیچ نوێکردنەوەیەک بەردەست نییە', messageEn: 'No updates available' });
      }
      return { success: true, updateAvailable: false, version: currentVersion };
    }
  } catch (error) {
    if (mainWindow && mainWindow.webContents) {
      mainWindow.webContents.send('update-status', { status: 'error', message: 'هەڵەیەک ڕوویدا', messageEn: 'Error checking for updates' });
    }
    return { success: false, error: error.message };
  }
});

ipcMain.handle('download-update', async () => {
  try {
    if (!latestReleaseInfo) throw new Error('No release info available');
    const exeAsset = latestReleaseInfo.assets.find(a => a.name.endsWith('.exe') && !a.name.includes('blockmap'));
    if (!exeAsset) throw new Error('No installer found');

    if (mainWindow && mainWindow.webContents) {
      mainWindow.webContents.send('update-status', { status: 'downloading', message: 'داگرتن... 0%', messageEn: 'Downloading... 0%', percent: 0 });
    }

    downloadedFilePath = await downloadAsset(exeAsset.id, exeAsset.name, exeAsset.size);
    
    if (mainWindow && mainWindow.webContents) {
      mainWindow.webContents.send('update-status', { status: 'downloaded', message: 'نوێکردنەوە ئامادەیە', messageEn: 'Update ready to install' });
    }
    return { success: true };
  } catch (error) {
    if (mainWindow && mainWindow.webContents) {
      mainWindow.webContents.send('update-status', { status: 'error', message: 'هەڵەیەک ڕوویدا', messageEn: 'Error downloading' });
    }
    return { success: false, error: error.message };
  }
});

ipcMain.handle('install-update', () => {
  if (downloadedFilePath && fs.existsSync(downloadedFilePath)) {
    const { spawn } = require('child_process');
    spawn(downloadedFilePath, [], { detached: true, stdio: 'ignore' }).unref();
    app.quit();
  }
});

// Background removal - not supported
ipcMain.handle('remove-background', async () => {
  return { success: false, error: 'Background removal not available in desktop app.', notSupported: true };
});

// ============================================
// PROTECTED FEATURES - REQUIRE LICENSE
// ============================================

// Check if action is allowed (for renderer to verify before actions)
ipcMain.handle('check-feature-access', async (event, feature) => {
  if (!isLicenseValid) {
    return { allowed: false, error: 'LICENSE_REQUIRED' };
  }
  return { allowed: true };
});

// Periodic license re-verification (called from renderer)
ipcMain.handle('verify-license-state', async () => {
  // Re-check license from file to ensure it wasn't tampered
  const machineId = cachedMachineId || getHardwareMachineId();
  if (!machineId) {
    isLicenseValid = false;
    return { valid: false };
  }
  
  const storedLicense = loadLicenseFromFile(machineId);
  if (!storedLicense || !storedLicense.token || !isTokenValid(storedLicense.token)) {
    isLicenseValid = false;
    return { valid: false };
  }
  
  isLicenseValid = true;
  return { valid: true };
});

// ============================================
// APP LIFECYCLE
// ============================================

app.on('open-file', (event, filePath) => {
  event.preventDefault();
  if (mainWindow) openProjectFile(filePath);
  else fileToOpen = filePath;
});

// Allow multiple instances of the app
app.whenReady().then(() => {
  const argv = process.argv;
  const filePath = argv.find((arg) => arg.endsWith('.pppro'));
  if (filePath) fileToOpen = filePath;
  createWindow();
});

app.on('window-all-closed', async () => {
  await stopHeartbeat();
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', async () => {
  await stopHeartbeat();
});

app.on('activate', () => {
  if (mainWindow === null) createWindow();
});
