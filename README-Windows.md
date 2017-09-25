### Install instructions
Use a python 2.7 from cloudbase-init.

Install latest pexpect from github: https://github.com/pexpect/pexpect .

Install the lzma wheel: pip install -i https://pypi.anaconda.org/carlkl/simple backports.lzma .

### Run instructions
lava-dispatcher> python.exe .\lava\dispatcher\lava-dispatcher-slave --master `tcp:/<lava-server-ip>:5556` --socket-addr `tcp://<lava-server-ip>:5555`  --log-file ./lava.log


