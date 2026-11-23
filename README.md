# SecureVNC

Отдалечен достъп за Windows в локална мрежа: базиран на VNC (RFB протокол), с криптиране (TLS 1.3), локален сертификат (собствен CA на всеки сървър) и MFA с Google Authenticator.

## Части

| Проект | Какво е |
|---|---|
| `SecureVNC.Service` | Windows услуга (SYSTEM, автоматичен старт). Пуска агента в активната конзолна сесия, рестартира го при смяна на сесията, изпълнява Ctrl+Alt+Del. |
| `SecureVNC.Server` | Агентът (`--agent`, стартиран от услугата като SYSTEM) или самостоятелно tray приложение. Заснема екрана, приема връзки, изпълнява мишка/клавиатура, следи активния desktop (Default ↔ Winlogon). Показва известие при всяко свързване. |
| `SecureVNC.Manager` | Графично управление: потребители с QR код, сертификат, услуга. |
| `SecureVNC.Admin` | Същото от конзолата: `init`, потребители, сертификати. |
| `SecureVNC.Client` | Програмата, с която се свързваш. |
| `SecureVNC.Shared` | Протокол, TOTP, пароли, сертификати. |
| `installer/SecureVNC.iss` | Setup програмата (Inno Setup). |
| `tests/SecureVNC.SelfTest` | End-to-end тест: истински сървър + клиент на loopback. |

## Сигурност

- **Криптиране**: целият RFB трафик минава през TLS 1.2/1.3 (на практика TLS 1.3, AES-256-GCM).
- **Локален сертификат**: `init` създава CA `SecureVNC CA <компютър>` (ECDSA P-256, 10 г.) и сертификат на сървъра за името и IPv4 адресите му. При смяна на IP сертификатът се преиздава автоматично. Клиентът доверява CA-то, а не конкретния сертификат.
- **Първо свързване**: клиентът показва SHA-256 отпечатъка на CA → сравни с `SecureVNC.Admin cert show` на сървъра. След това се помни за този адрес (като SSH known_hosts). Ако CA-то се смени → голямо предупреждение. Може и предварително: `export-ca` → бутон **Import CA...** в клиента.
- **Проверка преди тайни**: паролата и кодът се пращат само след като сертификатът е проверен (име/IP + верига до доверено CA).
- **MFA**: парола (PBKDF2-SHA256, 210 000 итерации) + 6-цифрен TOTP код (RFC 6238, съвместим с Google Authenticator). Всеки код важи само веднъж.
- **Защита от отгатване**: 5 грешни опита → блокиране на IP адреса и потребителя за 5 минути, 1 s забавяне при грешка.
- **Само локална мрежа**: сървърът отказва адреси извън частните мрежи (`allowedNetworks` в config) + правило във Firewall само за `LocalSubnet`.
- **Тайни на диска**: TOTP seed-ове и частни ключове са криптирани с DPAPI (machine), папката `%ProgramData%\SecureVNC` е достъпна само за Administrators и SYSTEM.

## Инсталация (лесният начин)

Един файл: `SecureVNC-Setup-1.0.0.exe`. Двоен клик → избираш:

- **Server and client** – този компютър ще може и да бъде управляван, и да управлява други;
- **Server only** – компютърът, който ще бъде управляван;
- **Client only** – само програмата за свързване.

Сървърната част сама създава локалния сертификат, услугата `SecureVNC`, правилото във Firewall (само локалната мрежа) и политиката за Ctrl+Alt+Del. Накрая се отваря **SecureVNC Manager** за първия потребител: име, парола, QR код за Google Authenticator и проверка с код от телефона.

После Manager е в Start менюто. В него: потребители (добавяне, парола, нов телефон, изтриване), отпечатък на сертификата, **Export CA for clients...**, статус и рестарт на услугата, логове.

Обновяване: пускаш новия Setup върху стария – потребителите и сертификатите остават. Премахване: **Settings → Apps → SecureVNC**; пита дали да изтрие и потребителите/сертификатите (по подразбиране – не).

Ако мрежата е **Public**, Setup предупреждава: Windows блокира входящите връзки там → направи я Private.

## Build

```powershell
dotnet build
dotnet run --project tests\SecureVNC.SelfTest
.\scripts\build-installer.ps1   # -> dist\SecureVNC-Setup-<версия>.exe (иска Inno Setup 6)
```

`build-installer.ps1 -Version 1.1.0` за нова версия. `scripts\publish.ps1` прави само `dist\Server` и `dist\Client` (self-contained, без .NET на целевите машини).

Ръчна инсталация без Setup: `dist\Server\install-server.ps1` като администратор (`uninstall-server.ps1` за премахване). Двата пътя ползват `configure-server.ps1`.

## Как работи сървърът

Услугата не слуша в мрежата. Тя стартира `SecureVNC.Server.exe --agent` като SYSTEM в конзолната сесия (в job, който умира с нея). Агентът превключва нишките си към текущия input desktop (Default ↔ Winlogon), затова работят екранът за вход, заключеният екран и UAC. При logoff или смяна на потребител агентът се рестартира в новата сесия, а клиентът трябва да се свърже наново с нов код.

Логове: `%ProgramData%\SecureVNC\logs\service-*.log`, `agent-*.log`, `manager-*.log`; лог от инсталацията: `C:\Program Files\SecureVNC\Server\setup.log`.

Управление от конзолата (като администратор), ако не искаш Manager:

```powershell
& "C:\Program Files\SecureVNC\Server\SecureVNC.Admin.exe" user add ivan
& "C:\Program Files\SecureVNC\Server\SecureVNC.Admin.exe" user list
& "C:\Program Files\SecureVNC\Server\SecureVNC.Admin.exe" cert show
```

Настройки: `%ProgramData%\SecureVNC\config.json` (`port`, `listenAddress`, `allowedNetworks`, `viewOnly`, `maxFailedAttempts`, `lockoutMinutes`, `maxFramesPerSecond`). След промяна: **Restart service** в Manager.

## Клиент

Стартирай **SecureVNC Client** (Start меню / Desktop) → компютър (име или IP), потребител, парола, код от Google Authenticator → **Connect**.
Бутони: Fit to window, Ctrl+Alt+Del (само в режим услуга), Win, Alt+Tab, Ctrl+Shift+Esc, Disconnect. Клавиатурата се праща като scan кодове, затова важи подредбата (BG/EN) на отдалечения компютър.

## Протокол (накратко)

TCP 5901 → TLS → RFB 3.8 → security type `0x80` (сървърът праща CA-то си; клиентът праща user + парола + TOTP) → стандартни RFB съобщения. Разширения: encoding `-512` (zlib на правоъгълник), client message `250` (Windows клавиш), `251` (Ctrl+Alt+Del), DesktopSize `-223`.

## Ограничения (следващи стъпки)

- При смяна на сесията (logoff, смяна на потребител) връзката пада; клиентът още не се свързва автоматично наново.
- Агентът показва tray иконка като SYSTEM; менюто ѝ нарочно има само информация и „Disconnect all“.
- Няма clipboard и прехвърляне на файлове.
- Заснемане през GDI (стабилно, но по-бавно); следва DXGI Desktop Duplication за по-висок FPS.
- Клавишът Win и Alt+Tab се хващат от локалния Windows, затова са бутони (low-level keyboard hook по-късно).
- Блокирането по потребител позволява на някой в мрежата нарочно да заключва акаунт за 5 минути.
