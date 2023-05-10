copy "%~dp0KernelHack.sys" "C:\KernelHack.sys"
sc create KernelHack binPath= "\??\c:\KernelHack.sys" type= "kernel" start= "demand"
sc start KernelHack
sc delete KernelHack
