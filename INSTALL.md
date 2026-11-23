# SecureVNC – Installation guide

This guide walks you through installing SecureVNC step by step, in the right order.

- [1. Before you start](#1-before-you-start)
- [2. Choose a mode](#2-choose-a-mode)
- [3. Mode A – local users (a few computers)](#3-mode-a--local-users-a-few-computers)
- [4. Mode B – central Auth Server (many computers)](#4-mode-b--central-auth-server-many-computers)
- [5. Connecting](#5-connecting)
- [6. Everyday administration](#6-everyday-administration)
- [7. Cloned computers and images](#7-cloned-computers-and-images)
- [8. Updating and uninstalling](#8-updating-and-uninstalling)
- [9. Troubleshooting](#9-troubleshooting)
- [10. Security checklist](#10-security-checklist)

---

## 1. Before you start

**Download** from [Releases](https://github.com/neikovo/SecureVNC/releases/latest):

| File | Use |
|---|---|
| `SecureVNC-Setup-<version>.exe` | Installer for Server, Client and Auth Server |
| `SecureVNC-Client-Portable.zip` | Client without installation (e.g. on a USB stick) |

Compare the SHA-256 shown in the release notes. The files are not code-signed, so Windows SmartScreen may warn: **More info → Run anyway**.

**Requirements**

| | |
|---|---|
| Computers to control | Windows 10/11 x64, local administrator for the installation |
| Auth Server (mode B) | Windows Server 2019/2022 (or Windows 10/11) with a fixed IP address or DNS name |
| Your computer | Windows 10/11 x64 |
| Phone | Google Authenticator (or any TOTP app), one per administrator |
| Network | Local network, profile **Private** or **Domain** (Windows blocks incoming connections on **Public**) |
| Ports | TCP **5901** to each controlled computer, TCP **5902** to the Auth Server (mode B) |

No .NET installation is needed; everything is included.

## 2. Choose a mode

| | **Mode A – local** | **Mode B – central** |
|---|---|---|
| Users are kept | on each computer | on one Auth Server |
| Who checks a login | the computer itself | the Auth Server (the computer only gets a signed ticket) |
| Best for | 1–5 computers, home, small office | many computers, several administrators |
| Adding / removing an administrator | on every computer | once |

You can switch a computer between modes later (SecureVNC Manager → **Join auth server…** / **Leave auth server**).

---

## 3. Mode A – local users (a few computers)

### Step 1 – each computer you want to control

1. Run `SecureVNC-Setup-<version>.exe` and confirm the UAC prompt.
2. Choose **Server only**.
3. On the page **Central authentication (optional)** leave all three fields **empty**.
4. Finish the setup. **SecureVNC Manager** opens:
   - Create your user: name, password (at least 10 characters), scan the QR code with Google Authenticator, enter the code.
   - Note the computer's **name / IP address** shown at the top.
   - Click **Export CA for clients…** and save the `.cer` file (e.g. to a USB stick).

### Step 2 – your computer

1. Run the setup and choose **Client only** (or unzip the portable client).
2. Start **SecureVNC Client** and click **Import CA…** for each `.cer` file from step 1.
   (Without importing, the client shows the certificate fingerprint on the first connection; compare it with the one in SecureVNC Manager on that computer.)

Continue with [5. Connecting](#5-connecting).

---

## 4. Mode B – central Auth Server (many computers)

Install in this order: **Auth Server → computers → your client.**

### Step 1 – the Auth Server

1. On the server run the setup and choose **Auth Server**.
2. Finish the setup. **SecureVNC Auth Console** opens and asks for a **master password**:
   - At least 12 characters; a sentence of several words is good.
   - It encrypts all secrets of the Auth Server and is **not stored anywhere**.
   - **It cannot be recovered.** Write it down and keep it in a safe place. Without it the Auth Server cannot be unlocked and every computer must join a new one.
3. Add the first administrator: name, password, scan the QR code, enter the code. Add more administrators the same way (tab **Administrators**).
4. Note these three values from the Auth Console (you need them for every computer):
   - **Address** – the server's name or IP address ("Computers connect to: …")
   - **CA fingerprint** – **Copy fingerprint**
   - **Join key** – **Show / hide join key** or **Copy join key** (keep it secret: anyone with it can join a computer)
5. Click **Export CA for clients…** and save `SecureVNC-Organization-CA.cer`.
6. Optional: tab **Computers** → tick **New computers need my approval…** if every new computer should wait for your OK.

> **After every restart of the Auth Server** (e.g. Windows updates) it is **locked**: nobody can log in anywhere. Open the Auth Console and enter the master password.

### Step 2 – each computer you want to control

**Interactive:**
1. Run the setup and choose **Server only**.
2. On the page **Central authentication (optional)** enter the **address**, **CA fingerprint** and **join key** from step 1.
3. Finish the setup. SecureVNC Manager opens and shows "Auth server …: reachable. This computer is registered as …".

**Silent (many computers, script, GPO, Intune):**

```powershell
SecureVNC-Setup-1.4.0.exe /VERYSILENT /COMPONENTS=server /AUTHSERVER=srv01 /AUTHFP=AB:CD:...:EF /JOINKEY=XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
```

**Later, on an already installed computer:** SecureVNC Manager → **Join auth server…**, or as administrator:

```powershell
& "C:\Program Files\SecureVNC\Server\SecureVNC.Admin.exe" join srv01 AB:CD:...:EF XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
```

If approval is required, the computer appears as **WAITING** in the Auth Console → tab **Computers** → **Approve / allow**.

### Step 3 – your computer

1. Run the setup and choose **Client only** (or unzip the portable client).
2. Start **SecureVNC Client** → **Import CA…** → choose `SecureVNC-Organization-CA.cer` from step 1. This one file makes the client trust every joined computer.
3. Make sure your computer can reach the Auth Server on port **5902** (the client gets its ticket there).

---

## 5. Connecting

1. Start **SecureVNC Client**.
2. Enter the **computer** (name or IP), **port** `5901`, your **user name**, **password** and the current **6-digit code** from Google Authenticator.
3. Click **Connect**.

Notes:
- Every connection needs a **new code**; a code works only once (wait for the next one if you connect twice within 30 seconds).
- The status line in the viewer shows how you logged in, e.g. *ticket from srv01*.
- On the controlled computer the tray icon turns **red** while someone is connected and shows a notification; it is **green** when nobody is connected. Hovering over it shows its IP address and port.
- Login screen / lock screen: use the **Ctrl+Alt+Del** button, then log in to Windows.
- If the user on that computer logs off or switches user, the connection ends; connect again with a new code.
- **Emergency login** (checkbox) is only for a local emergency account on a computer in mode B. Leave it off normally.
- After a successful login you get screen, mouse and keyboard only. There is no file transfer or clipboard.

---

## 6. Everyday administration

| Task | Where |
|---|---|
| Add / remove an administrator, new phone, new password | Mode A: SecureVNC Manager on each computer. Mode B: Auth Console → **Administrators** |
| Block a computer (lost, stolen, retired) | Auth Console → **Computers** → **Block** (its certificate expires within 7 days and cannot be renewed) |
| See who logged in where | Auth Console → **Audit** |
| New join key (old one leaked) | Auth Console → **New join key…** (joined computers keep working) |
| Lock the Auth Server immediately | Auth Console → **Lock now** |
| Change the master password | Auth Console → **Change master password…** |
| Disconnect everyone from a computer | Tray icon → **Disconnect all**, or SecureVNC Manager → **Restart service** |
| Service status / restart | SecureVNC Manager or Auth Console, or `services.msc` (*SecureVNC Server*, *SecureVNC Auth Server*) |

SecureVNC Manager and the Auth Console ask for a SecureVNC login (password + code) and close after 10 minutes without activity.

---

## 7. Cloned computers and images

- You can install SecureVNC (joined to the Auth Server) **before** taking the image, or install it after cloning.
- On first start a clone notices that its computer name or Windows machine GUID changed, creates its own keys and joins the Auth Server again with the saved join key.
- Give every clone its **own computer name** (Windows requires this on the network anyway). A clone that still has the original's name is treated as the same computer.
- An image contains the join key. Treat images as confidential; after an image leaks, create a **New join key** and update the image.

---

## 8. Updating and uninstalling

**Updating:** run the new setup over the old one. Users, keys and certificates are kept.

- Auth Server updated from 1.2.x/1.3.x: the Auth Console asks you to set a **master password** and seals the existing keys. The Auth Server stays locked until you do.

**Uninstalling:** **Settings → Apps → SecureVNC**. You are asked whether to delete users, keys and certificates as well (default: keep them, so a reinstall works with the same clients).

---

## 9. Troubleshooting

**Logs**

| Where | What |
|---|---|
| `%ProgramData%\SecureVNC\logs\` | `service-*.log`, `agent-*.log`, `manager-*.log` (controlled computer) |
| `%ProgramData%\SecureVNC-Auth\logs\` | `auth-*.log`, `audit-YYYYMM.log` (Auth Server) |
| `C:\Program Files\SecureVNC\Server\setup.log` | output of the installation |
| Windows Event Log (Application) | problems with the data folder (see below) |

**Common problems**

| Message / symptom | Cause and fix |
|---|---|
| No connection at all | Network profile **Public**, firewall, wrong port, or the computer is off. Set the network to Private. |
| "The SecureVNC authentication server is not reachable" | Auth Server off, **locked** (enter the master password in the Auth Console), or port 5902 blocked from your computer. |
| "Authentication failed." | Wrong user, password or code, or the code was already used. Wait for the next code. |
| "Too many failed attempts" | 5 failures lock the account and your address for 5 minutes. |
| "… does not have a certificate from your organization's auth server" | The computer is not joined (or it is an impostor). Join it, or use Emergency login only if it really uses local accounts. |
| "This computer is blocked in the Auth Console" / "waits for approval" | Auth Console → Computers → **Approve / allow**. |
| "A computer named … is already registered" | Another computer used this name. Delete the old entry in the Auth Console, or rename the computer. |
| Services do not start, Event Log says the data folder is not trustworthy | Something in `%ProgramData%\SecureVNC` was not created by an administrator. Delete the folder as administrator and run the setup again. |
| The RDP session to the computer ends when you log in with SecureVNC | Normal Windows behaviour: Windows 10/11 allows one active session, so logging in at the console takes the user's RDP session over. |

---

## 10. Security checklist

- [ ] Networks set to **Private** or **Domain**, not Public.
- [ ] Administrators use long passwords and their own phone for Google Authenticator.
- [ ] Mode B: the Auth Server is a dedicated machine with few administrators, current updates, BitLocker, and a firewall that allows only port 5902 from the LAN.
- [ ] The **master password** is written down and stored safely (e.g. a safe, or two sealed envelopes with two people).
- [ ] The **join key** is shared only with the people who install computers; change it when it may have leaked.
- [ ] Clients have the organization CA imported (no "trust this certificate?" questions in everyday use).
- [ ] Lost or retired computers are **blocked** in the Auth Console.
- [ ] The **Audit** tab is checked regularly.

For how SecureVNC works and how it is protected, see [README.md](README.md) (Bulgarian). Planned features: [ROADMAP.md](ROADMAP.md).
