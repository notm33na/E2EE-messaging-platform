# Installing mkcert for Trusted Local Certificates

To eliminate browser security warnings, you need to install `mkcert` on your system.

## Option 1: Using Chocolatey (Recommended for Windows)

1. Install Chocolatey (if not already installed):

   - Open PowerShell as Administrator
   - Run: `Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))`

2. Install mkcert:

   ```powershell
   choco install mkcert
   ```

3. Install the local CA:
   ```powershell
   mkcert -install
   ```

## Option 2: Using Scoop

1. Install Scoop (if not already installed):

   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   irm get.scoop.sh | iex
   ```

2. Install mkcert:

   ```powershell
   scoop install mkcert
   ```

3. Install the local CA:
   ```powershell
   mkcert -install
   ```

## Option 3: Manual Installation

1. Download mkcert from: https://github.com/FiloSottile/mkcert/releases
2. Download `mkcert-v*-windows-amd64.exe` for Windows
3. Rename it to `mkcert.exe` and add it to your PATH
4. Run `mkcert -install` in PowerShell as Administrator

## After Installation

Once mkcert is installed, restart your Vite dev server:

```powershell
npm run dev
```

The `vite-plugin-mkcert` plugin will automatically generate trusted certificates that include your local IP address, eliminating browser security warnings.

## Note

If you prefer to keep using self-signed certificates (which work but show warnings), you can revert to the previous configuration. The current setup with `vite-plugin-mkcert` is recommended for the best development experience.
