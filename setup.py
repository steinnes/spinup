from setuptools import setup

import os


def parse_requirements(filename):
    reqs = []
    with open(filename) as f:
        for req in f.readlines():
            if req.startswith("#"):
                continue
            reqs.append(req.replace("\n", ""))
    return reqs


def get_requirements():
    requirements = parse_requirements(
        os.path.join(os.path.dirname(__file__), "requirements.txt")
    )
    return [str(req) for req in requirements if not req.startswith("-e ")]


setup(
    name='spinup',
    version='0.1.0',
    description='',
    py_modules=['spinup'],
    install_requires=get_requirements(),
    entry_points='''
        [console_scripts]
        spinup=spinup:cli
    '''
)
