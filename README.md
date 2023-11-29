# FreeLoaderInjector
Typical Process Injection using a Opened Handle Process by other process, and founding a RWX Memory Space in some of the opened processes!

![image](https://github.com/S12cybersecurity/FreeLoaderInjector/assets/79543461/7bcdec8d-f761-4cdc-9c14-db08f60f1fb5)

The shellcode its a calc.exe popup encrypted with XOR, at the moment (29/11/2023) it's bypassing Windows Defender, if you want more evasion you can implement other encryption method like AES, RC5 or others.

![image](https://github.com/S12cybersecurity/FreeLoaderInjector/assets/79543461/666eea91-8d83-48ee-89dd-b7dbf755bcc8)

Finally a posible extension (i want to add before 2024) it's using a opened thread (the function are implemented in MapMemoryHandlers.h) and perform a Threat Hijacking attack to avoid the use of CreateRemoteThread function.
