from setuptools import setup, find_packages

setup(
    name="rayhunter-threat-analyzer",
    version="2.1.0",
    author="Julian Burns",
    description="Forensic cellular surveillance detection tool for Rayhunter captures",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "pyyaml>=6.0",
        "requests>=2.28.0",
        "rich>=13.0.0",
        "pyshark>=0.6.0",
        "python-dateutil>=2.8.2",
    ],
    entry_points={
        "console_scripts": [
            "rayhunter-analyze=main:main",
        ],
    },
)
