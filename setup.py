from setuptools import setup, find_packages

setup(
    name="fptail",
    version="0.1.0",
    description="tail(1)-style live/stored log viewer for Forcepoint NGFW SMC",
    packages=find_packages(include=["fptail", "fptail.*"]),
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
            "fptail=fptail.cli:main",
        ],
    },
)
