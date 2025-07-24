# Network Automation Inventory

**Private script – not publicly available**

Contact: bondansvbianca@gmail.com

This repository is related to the **Discovers project**, which automates device login and collects:

- Hostnames
- Vendors
- Models
- Serial numbers
- Locations

It generates both **Excel** and **JSON** files with the data collected from each IP address.

---

##  Libraries used

```python
# -*- coding: utf-8 -*-
import pandas as pd
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from concurrent.futures import ThreadPoolExecutor
import json
from threading import Lock
import re
import time
import paramiko.ssh_exception
from netmiko.ssh_autodetect import SSHDetect
import paramiko

