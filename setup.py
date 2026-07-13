from setuptools import setup, find_packages

setup(
    name="fp",
    version="0.2.0",
    description="Forcepoint NGFW SMC command-line tools: log tailing, license inventory",
    packages=find_packages(include=["fp", "fp.*"]),
    python_requires=">=3.8",
    install_requires=[
        "fp-NGFW-SMC-python>=1.0.33",
        "fp-NGFW-SMC-python-monitoring>=1.5.6",
        "websocket-client>=1.8.0",
        "packaging",
        "urllib3",
    ],
    entry_points={
        "console_scripts": [
            "fp=fp.cli:main",
        ],
    },
)
