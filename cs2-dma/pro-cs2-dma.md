# Analysis: `pro-cs2.exe` (Pro-CS2 DMA Cheat Loader)

## 📌 Summary
- **File name:** `pro cs2.exe`
- **SHA-256:** `[your hash here]`
- **Type:** PE64 Windows Console Application
- **Compiler:** MSVC++ (Visual Studio 2022)
- **Purpose:** DMA cheat loader for CS2
- **Risk:** Suspicious; memory manipulation & encryption logic observed

---

## 🔍 Key Findings

### 1. Strings of Interest
- Hardcoded URLs to CS2 offset dumpers:
  - `https://raw.githubusercontent.com/a2x/cs2-dumper/...`
- Mentions of: `password`, `CryptEncrypt`, `Memory encryption detected`

### 2. API Calls (Suspicious)
- `GetAsyncKeyState` (keylogging)
- `CryptEncrypt`, `CryptHashData`, `CryptImportKey` (crypto)
- `ShellExecuteA`, `CreateFileA`, `GetProcAddress`

### 3. No Obvious Signs Of:
- `CreateRemoteThread`, `WriteProcessMemory`, `VirtualAllocEx`

---

## 🔐 Indicators of Compromise (IOCs)

See [`pro-cs2-dma-iocs.txt`](./pro-cs2-dma-iocs.txt)

---

## 🛡️ YARA Rule

See [`pro-cs2-dma.yara`](./pro-cs2-dma.yara)
