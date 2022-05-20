# Inspiration
Following [this tutorial](https://github.com/stong/CVE-2020-15368), this is my attempt at learning how to exploit a vulnerable windows driver. A **driver** is kind of like a mediator between user programs and the kernel. User programs make *IRPs*, or I/O request packets (also called ioctls on Linux) to drivers, which then go out and do that request. The only difference is, drivers have access to *kernel mode routines*, available to use in the <wdm.h> header by Microsoft. This grants drivers a lot of power in what they can do, allowing us to interact 

## To run this exploit:

1. The driver itself is available at the ASROCK website, and is called "AsrDrv104.sys" when installed properly. To install it, go to 

You can see it running in [Process Hacker 2](https://processhacker.sourceforge.io/downloads.php) under the services tab
![image](https://user-images.githubusercontent.com/69275171/169472021-42cd50a9-7428-4568-b334-fa8faa380420.png)

