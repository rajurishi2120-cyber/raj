from setuptools import setup, find_packages

setup(
    name="raj",
    version="1.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "rich",
        "colorama",
        "urllib3"
    ],
    entry_points={
        "console_scripts": [
            "raj=raj.main:cli"
        ]
    },
    author="Mr Raj",
    description="Multi Advance Scanner Tool",
)