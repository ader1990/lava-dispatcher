import logging
import os
import signal

from lava_dispatcher.pipeline.shell import (
    ShellSession
)


class CustomShellSession(ShellSession):
    """ Wrapper with finalise lambda over ShellSession"""

    def __init__(self, job, shell_command):
        super(CustomShellSession, self).__init__(job, shell_command)
        self.logger = logging.getLogger('dispatcher')
        self.onfinalise = None

    def finalise(self):
        self.logger.info("Terminating shell session ...")
        if self.onfinalise:
             self.logger.debug("Executing finalise...")
             self.onfinalise()
        if self.raw_connection:
            try:
                os.killpg(self.raw_connection.pid, signal.SIGKILL)
                self.logger.debug("Finalizing child process group with PID %d" % self.raw_connection.pid)
            except OSError:
                self.raw_connection.kill(9)
                self.logger.debug("Finalizing child process with PID %d" % self.raw_connection.pid)
            self.raw_connection.close()

