# The DrK (De-randomizing Kernel ASLR) attack
DrK is an attack that breaks kernel address space layout randomization (KASLR)
by exploiting TLB and decoded i-cache side channel. To reliably exploit the
side channels, the DrK attack took advantage of
Intel TSX (Transactional Synchronization eXtension).
One surprising behavior of TSX, which is essentially
the root cause of this security loophole, is that it aborts a
transaction without notifying the underlying kernel even when the
transaction fails due to a critical error, such as a page fault or an
access violation, which traditionally requires kernel intervention.
DrK turns this property into a precise timing channel that can
determine the mapping status (i.e., mapped versus unmapped) and
execution status (i.e., executable versus non-executable) of the privileged
kernel address space. Since such behavior is on the hardware level,
DrK is universally applicable to all OSes, even in
virtualized environments, and generates no visible footprint, making
it difficult to detect in practice.
Therefore, DrK can break
the KASLR of all major OSes (i.e., Windows, Linux, and OS X)
with near-perfect accuracy in under a second.


## More details
* DrK paper (ACM CCS'16): http://people.oregonstate.edu/~jangye/assets/papers/2016/jang:drk-ccs.pdf
* Talk at Black Hat USA: https://www.youtube.com/watch?v=rtuXG28g0CU

## Demo

### Timing (click the image to watch the video)
[![Timing Demo](https://img.youtube.com/vi/NdndV_cMJ8k/0.jpg)]
(https://www.youtube.com/watch?v=NdndV_cMJ8k)

### Full attack on Linux (click the image to watch the video)
[![Full attack on Linux](https://img.youtube.com/vi/WXGCylmAZkA/0.jpg)]
(https://www.youtube.com/watch?v=WXGCylmAZkA)

## Build
Run ```make``` on the directory of this repository.

### Example: Timing demo
Run ```cd timing; ./timing_demo.py```
<p align='left'>
<img width="60%" src="https://github.com/sslab-gatech/DrK/blob/master/timing-mu.png" /><br />
<img width="60%"  src="https://github.com/sslab-gatech/DrK/blob/master/timing-x-nx.png" /><br />
</p>

### Example: Breaking KASLR in Linux
Run ```cd linux; ./run-drk-attack.py```
<p align='left'>
<img width="60%" src="https://github.com/sslab-gatech/DrK/blob/master/linux-attack.png" /><br />
</p>

## Contributors
* [Yeongjin Jang]
* [Sangho Lee]
* [Taesoo Kim]

[Yeongjin Jang]: <http://people.oregonstate.edu/~jangye>
[Sangho Lee]: <http://www.cc.gatech.edu/~slee3036>
[Taesoo Kim]: <https://taesoo.gtisc.gatech.edu>
