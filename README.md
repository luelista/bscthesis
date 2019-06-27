# Optimizing Cooperation of HTTP/2 and Multipath TCP
Bachelor thesis by Mira Weller

## Abstract
Multipath TCP is an extension to the Transmission Control Protocol (TCP) to support the use of multiple paths between
hosts with multiple interfaces. An implementation of Multipath TCP has to decide for each data segment over which path
it should be sent. This decision can be based on different criteria and algorithms, making a trade-off between throughput,
resource utilization, reliability, delay and jitter. Even though Multipath TCP has fully backwards compatibility towards
the applications layer, we can reap performance benefits by enabling the application to select a scheduling algorithm
based on its internal information about content types, priorities, dependencies and user expectations. Therefore, we
modify a HTTP/2 web server to pass scheduling hints to the Multipath TCP scheduler via socket options. The scheduling
algorithms are developed in a scripting language for easier evaluation. An evaluation is performed in simulated and
real-world environments over LTE and WiFi.

## Source code

* [Patched web server (nghttpd)](https://github.com/luelista/nghttpd-mptcp)
* [MACI framework](https://github.com/AlexanderFroemmgen/maci)

