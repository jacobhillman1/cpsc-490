# Implementing a Maglev Boad Balancer in the Linux Kernel
This is code relating to my senior thesis.

## Asdding the Module
1. Run `make` in the directory containing load_balancer.c and the Makefile.
2. Add the module onto the kernel using `insmod`. The module expects to be passed a list of backends for the load balancer to distribute traffic to. The list of backend addresses is passed in using the `backend_addrs` param. For example, 
```
sudo insmod load_balancer.ko backend_addrs=127.0.0.1:6789,130.132.171.22:4567
```
3. The module is now running in the kernel! All network traffic to the kernel running the module will be forwarded to one of the addresses passed in as a parameter.
4. To remove the module, run
```
sudo rmmod load_balancer
```
