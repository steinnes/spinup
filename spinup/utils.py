import boto3
import click
import shlex
import subprocess
import tempfile
import time
import os

from botocore.exceptions import ClientError
from contextlib import contextmanager


class Stack(object):
    def __init__(self, stack):
        self.stack = stack

    def __getitem__(self, key):
        return self.stack[key]

    @property
    def outputs(self):
        if hasattr(self, '_outputs'):
            return self._outputs

        self._outputs = {}
        for output in self['Outputs']:
            self._outputs[output['OutputKey']] = output['OutputValue']

        return self._outputs


def execute(cmd):
    if not isinstance(cmd, list):
        cmd = shlex.split(cmd)

    out = subprocess.check_output(cmd)
    return out


def get_stack(stackname):
    client = boto3.client('cloudformation')

    def _get_stack(stackname):
        try:
            resp = client.describe_stacks(StackName=stackname)
            stack = resp['Stacks'][0]
        except ClientError:
            return None
        return stack

    stack = _get_stack(stackname)
    if stack is None:
        click.echo("Can't find stack with name '{}'".format(stackname))
        resp = client.list_stacks(StackStatusFilter=['CREATE_IN_PROGRESS', 'CREATE_COMPLETE'])
        stacks = resp['StackSummaries']
        if len(stacks) > 0:
            click.echo("Did you mean one of these:")
            for stack in stacks:
                click.echo(" * {name}".format(name=stack['StackName']))
        return

    if stack['StackStatus'] == 'CREATE_IN_PROGRESS':
        click.echo("Stack creation in progress.", nl=False)
        while True:
            time.sleep(1)
            click.echo(".", nl=False)
            stack = _get_stack(stackname)
            if stack['StackStatus'] == 'CREATE_COMPLETE':
                break

    return Stack(stack)


@contextmanager
def template_file(tplfile, d):
    with tempfile.NamedTemporaryFile(mode='w') as tmpf:
        with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'tpl', tplfile)) as tplf:
            template = tplf.read()
        for key, value in d.items():
            template = template.replace('%{}%'.format(key), value)
        tmpf.write(template)
        tmpf.flush()
        yield tmpf.name


def snake_and_caps(string):
    def inner():
        start = True
        for c in string:
            if c.isupper():
                if not start:
                    yield '_'
                yield c
            else:
                yield c.upper()
            start = False
    return "".join(list(inner()))
