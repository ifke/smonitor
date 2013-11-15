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
    def __init__(self, path, parameters='', use_sudo=False, sudo_path=''):
        if not os.path.isfile(path):
            raise CommandError('The command file {path} not found'.format(**locals()))
        if not os.access(path, os.X_OK):
            raise CommandError('Can\'t execute the command file {path}'.format(**locals()))
        cmd_list = []
        if use_sudo:
            if not os.path.isfile(sudo_path):
                raise CommandError('The command file {sudo_path} not found'.format(**locals()))
            if not os.access(sudo_path, os.X_OK):
                raise CommandError('Can\'t execute the command file {sudo_path}'.format(**locals()))
            # we use -n options for sudo to disable password prompt
            cmd_list.extend([sudo_path, '-n'])
        cmd_list.append(path)
        if parameters:
            cmd_list.append(parameters)
        self.cmd_tmpl = ' '.join(cmd_list)

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
