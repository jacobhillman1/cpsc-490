# Implementing a Maglev Load Balancer in the Linux Kernel
This is code relating to my senior thesis.

## Adding the Module
1. **I highly recommend running the following in a virtual machine**. The code was developed and tested using [VirtualBox](https://www.virtualbox.org/) running Ubuntu 18.04 and Linux 4.18. Kernel programming is potentially harmful to the operating system -- though I'm *pretty sure* this code is safe, I'm new to kernel programming and don't want to accidentally harm your OS!
2. Run `make` in the directory containing load_balancer.c and the Makefile.
3. Add the module into the kernel using `insmod`. The module expects to be passed a list of backends for the load balancer to distribute traffic to. The list of backend addresses is passed in using the `backend_addrs` param. For example, 
```
sudo insmod load_balancer.ko backend_addrs=127.0.0.1:6789,130.132.171.22:4567
```
4. The module is now running in the kernel! All network traffic to the kernel running the module will be forwarded to the addresses passed in as a parameter.
5. To remove the module, run
```
sudo rmmod load_balancer
```
