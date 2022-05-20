# Inspiration
Following [this tutorial](https://github.com/stong/CVE-2020-15368), and more broadly, [this entire series](https://github.com/stong/memestream), this is my attempt at learning how to exploit a vulnerable windows driver. A **driver** is kind of like a mediator between user programs and the kernel. User programs make **IRPs**, or I/O request packets (also called ioctls on Linux) to drivers, which have special handler functions that are expecting these requests. Upon receiving a request, the driver does whatever it is it's meant to do- a network driver will process packets, a a mouse driver might deal with mouse interrupts. 

The significant part is- drivers have access to *kernel mode routines*, which on Windows, is available to use in the <wdm.h> header by Microsoft. This grants drivers a lot of power in what they can do, allowing us to interact directly with kernel objects. **This means it is very easy to bluescreen your computer if you make any mistake**!

This exploit attempts to "bypass" VAC by denying handles to CSGO, using something called **ObRegisterCallbacks**. This is a kernel mode routine that "calls back" a function, each time there is a handle operation on the system. And in Windows, a **handle** is kind of like a ticket to access something. Without handles, processes cannot access other processes. And this doesn't just go for processes. You can have a handle to a thread, a file, a mutex, an event- in fact, any object. **Objects** are an interesting topic in Windows, and I recommend reading Chapter 8 of [Windows Internals](https://www.amazon.com/Windows-Internals-Part-2-7th/dp/0135462401), or downloading [WinObjEx64](https://github.com/hfiref0x/WinObjEx64) to play around with them.

What this means is, we can monitor which processes are requesting handles to which other processes, and if the name of the process it is requesting a handle to is our target process, we will downgrade the handle permissions. If you want to change which program it denies handles to, change line 12 in Source.c:

```cpp
char* target_process = "csgo.exe";
```

## To run this exploit:

0. Download [Process Hacker 2](https://processhacker.sourceforge.io/downloads.php)

1. The driver itself is available at the ASROCK website. AsRock is just a motherboard manufacturing company, kind of like MSI. To install it, go to [this link](https://mega.nz/folder/oetQGSLS#ydUeesb9ixlcQjDjT7I3lA). If you're worried that it's a virus, don't be, because I uploaded it. It's just a extracted version of the correct AsRock driver (some of them install later versions, which may or may not have patched the vulnerability) which you can find on the [AsRock Support Site](https://www.asrock.com/MB/AMD/B550%20Taichi%20Razer%20Edition/Specification.asp#Download). All this driver does is work with the RGB lights on AsRock motherboards (another example of what drivers can do!) If you want to read more about why the driver is vulnerable, check out the [original author's post](https://github.com/stong/CVE-2020-15368). To summarize, it's because they massively over-engineered the driver by making it a template of the [Read/Write Everything](http://rweverything.com/) driver.

2. After obtaining the folder, go to Bin, then *run AsrPolychromeRGB*. This will install the driver (AsrDrv104.sys) onto your system. Don't worry if you don't have an AsRock motherboard, tons of drivers are completely useless and won't do anything if loaded. For example, the Null Driver, or the doskey driver. Or a CD-ROM driver, which comes by default in Windows, but obviously isn't being used if you don't have a CD-ROM.

![image](https://user-images.githubusercontent.com/69275171/169476954-d6bdccdc-7f81-44df-bdfb-9605c3e6e20f.png)

3. After installation finishes (don't worry if you get any error messages, we don't have the right motherboard so it will be confused), you should see "AsrDrv104.sys" in [Process Hacker 2](https://processhacker.sourceforge.io/downloads.php) under the services tab. Right click on it and click "Start". It should change to status "Running". The IOCTL handler is now ready to process requests from usermode programs!


![image](https://user-images.githubusercontent.com/69275171/169472021-42cd50a9-7428-4568-b334-fa8faa380420.png)

4. Open up the project in Visual Studio, run the project in Release. I'm not sure if Visual studio saves Configuration settings, but the projects titled "AsrDrvExploit" and "MyManualMapper" require C++17. Also, you need the [WDK](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) (Windows Driver Kit), which will provide the wdm.h header. There are a few more subtlties that may need to be figured out, setting up the driver kit can be a bit of a pain. I know it was for me.

5. Download [DebugView](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview), so we can see the output of the driver (since runs in kernel mode, the debug statements print to the kernel output). Setup your capture options like this.

![image](https://user-images.githubusercontent.com/69275171/169571995-b9ff3c9f-e3c6-4854-929c-4799f1e15a2d.png)

6. Finally, *run the driver* and watch all the handle requests on the system get printed out in DebugView. You can change which processes have access to your target process by altering the `isAllowedProgram` function in Source.c. The output looks like this:

![image](https://user-images.githubusercontent.com/69275171/169574847-63c8c2c5-0a46-4657-be15-ae6bb4e86d3f.png)

7. If you try to open your target process (here I used notepad.ex, you will see a spike in output, because the program is trying to deny all the handles that are being requested to your target process.

![image](https://user-images.githubusercontent.com/69275171/169574975-e4c4839b-067f-4f07-b544-84bfcd604772.png)

8. This program also *periodically scans all the handles* that exist to your target process, and strips them if they are not in the whitelist of functions and the permissions are too high. This is why the console output will keep moving down. To stop this, just disable autoscroll:

![image](https://user-images.githubusercontent.com/69275171/169575072-2aaaf690-7788-4af9-b815-fba64680d2a9.png)

8. To unload, just open a command prompt and type `doskey`. There's nothing special about running this in particular, in fact, the doskey driver is just another example of a driver that doesn't do anything (since it runs for DOS only). I just made it so that if the handle that is being requested is made to doskey, the driver will unload. Unload output looks like this:

![image](https://user-images.githubusercontent.com/69275171/169574647-e0803956-b385-4a3f-8658-7fd843bba8b4.png)

9. And there you go, we have a simple handle monitor that parellels something that a anti-cheat would do. Although, this is kind of like 2 projects in 1, because you can write whatever you would really like in Source.c, and *run whatever routines you would like in kernel mode*. This is the true power of this exploit!
