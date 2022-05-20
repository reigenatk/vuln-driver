# Inspiration
Following [this tutorial](https://github.com/stong/CVE-2020-15368), this is my attempt at learning how to exploit a vulnerable windows driver. A **driver** is kind of like a mediator between user programs and the kernel. User programs make *IRPs*, or I/O request packets (also called ioctls on Linux) to drivers, which then go out and do that request. The only difference is, drivers have access to *kernel mode routines*, available to use in the <wdm.h> header by Microsoft. This grants drivers a lot of power in what they can do, allowing us to interact 

## To run this exploit:

1. The driver itself is available at the ASROCK website. To install it, go to [this link](https://mega.nz/folder/oetQGSLS#ydUeesb9ixlcQjDjT7I3lA). If you're worried that it's a virus, don't be, because I uploaded it. It's just a extracted version of the correct AsRock driver (some of them install later versions, which may or may not have patched the vulnerability) which you can find on the [AsRock Support Site](https://www.asrock.com/MB/AMD/B550%20Taichi%20Razer%20Edition/Specification.asp#Download). All this driver does is work with the RGB lights on AsRock motherboards (another example of what drivers can do!) If you want to read more about why the driver is vulnerable, check out the [original author's post](https://github.com/stong/CVE-2020-15368). To summarize, it's because they massively over-engineered the driver by making it a template of the [Read/Write Everything](http://rweverything.com/) driver.

2. After obtaining the folder, go to Bin, then *run AsrPolychromeRGB*. This will install the driver (AsrDrv104.sys) onto your system. Don't worry if you don't have an AsRock motherboard, tons of drivers are completely useless and won't do anything if loaded. For example, the Null Driver, or the doskey driver. Or a CD-ROM driver, which comes by default in Windows, but obviously isn't being used if you don't have a CD-ROM.
![image](https://user-images.githubusercontent.com/69275171/169476954-d6bdccdc-7f81-44df-bdfb-9605c3e6e20f.png)

3. You can see it running in [Process Hacker 2](https://processhacker.sourceforge.io/downloads.php) under the services tab
![image](https://user-images.githubusercontent.com/69275171/169472021-42cd50a9-7428-4568-b334-fa8faa380420.png)

