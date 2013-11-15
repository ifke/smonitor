# -*- coding: utf-8 -*-


from __future__ import print_function
import os
from subprocess import Popen, PIPE


class CommandError(Exception):
    """
    Exception for command initialization
    """
    pass


def check_cmd(path):
    if not os.path.isfile(path):
        msg = 'The command file {path} not found'.format(**locals())
        raise CommandError(msg)
    if not os.access(path, os.X_OK):
        msg = 'Can\'t execute the command file {path}'.format(**locals())
        raise CommandError(msg)


class Command(object):
    """
    Help to run an external command

    The object stores a path to the command file and a template string
    of command parameters. On initilization it checks existance and
    mandatory properties of the command file. The object is callable
    and returns a tuple of return code and output of the command.
    """
    def __init__(self, path, parameters='', use_sudo=False, sudo_path=''):
        cmd_list = []
        if use_sudo:
            check_cmd(sudo_path)
            # we use -n options for sudo to disable password prompt
            cmd_list.extend([sudo_path, '-n'])
        check_cmd(path)
        cmd_list.append(path)
        if parameters:
            cmd_list.append(parameters)
        self.cmd_tmpl = ' '.join(cmd_list)

    def __call__(self, **kargs):
        """
        Fill the parameter template and run the command
        """
        cmd = self.cmd_tmpl.format(**kargs)
        pr = Popen(cmd.split(), stdout=PIPE, stderr=PIPE)
        pr.wait()
        rc = pr.returncode
        # if all is OK, it will return the standard output of the
        # command if there is an error on the command execution,
        # it will return the standard error output
        output = pr.communicate()[0] if rc == 0 else pr.communicate()[1]
        return (rc, output)

    def show(self, **kargs):
        """
        Fill the parameter template and return the command string
        """
        return self.cmd_tmpl.format(**kargs)
