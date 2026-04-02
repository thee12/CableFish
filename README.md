# CableFish (IN PROGRESS)

CableFish is a custom-made network packet sniffer that captures and inspects live network traffic. It contains a pipeline that captures the raw packets and processes them into readable data that individuals can get insights from.

Current Progress:
Capturing Packets - This has been implemented using the networking library libpcap in C++. It captures real-time traffic from a selectable network interface using the CLI.

Parsing Protocol Headers - Parsing Ethernet, IP, TCP/UDP and extracting source and destination IP addresses, port numbers, and protocol types.

Annotation Pipelin - Designing a pipeline to have readable annotations to interpret TCP flags and port-based identification.

Future:
Logging System
Export System
Rule-Based Detection

