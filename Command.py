# -*- coding: utf-8 -*-


from __future__ import print_function
import os, stat
from subprocess import Popen, PIPE


class CommandError(Exception):
    """
    Exception for command initialization
    """
    pass


class Command(object):
    """
    Help to run an external command

    The object stores a path to the command file and a template string of command parameters.
    On initilization it checks existance and mandatory properties of the command file.
    The object is callable and returns a tuple of return code and output of the command.
    """
    def __init__(self, path, parameters='', run_as_root=False):
        if not os.path.isfile(path):
            raise CommandError('The command file {path} not found'.format(**locals()))
        if not os.access(path, os.X_OK):
            raise CommandError('Can\'t execute the command file {path}'.format(**locals()))
        if run_as_root:
            cmd_stats = os.stat(path)
            if not (cmd_stats.st_mode & stat.S_ISUID and cmd_stats.st_uid == 0):
                raise CommandError('File {path} must be owned by root and has suid bit'.format(**locals()))
        self.cmd_tmpl = ' '.join((path, parameters)) if parameters else path

    def __call__(self, **kargs):
        """
        Fill the parameter template and run the command 
        """
        cmd = self.cmd_tmpl.format(**kargs)
        process = Popen(cmd.split(), stdout = PIPE, stderr = PIPE)
        process.wait()
        returncode = process.returncode
        # if all is OK, it will return the standard output of the command
        # if there is an error on the command execution, it will return the standard error output
        output = process.communicate()[0] if returncode == 0 else process.communicate()[1]
        return (returncode, output)

    def show(self, **kargs):
        """
        Fill the parameter template and return the command string (for debug purpose)
        """
        return self.cmd_tmpl.format(**kargs)
