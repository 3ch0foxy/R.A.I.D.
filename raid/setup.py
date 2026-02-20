from setuptools import setup, find_packages

try:
    with open("README.md", "r", encoding="utf-8") as fh:
        long_description = fh.read()
except FileNotFoundError:
    long_description = ""

setup(
    name="raid",
    version="1.0.0",
    author="Foxy",
    description="R.A.I.D. - A lightweight threat hunting framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.11",
    "Topic :: Security",
    ],
    python_requires=">=3.7",
    install_requires=[
        "pyyaml>=6.0.1",
        "python-evtx>=0.8.1",
    ],
    entry_points={
        "console_scripts": [
            "raid=raid.cli:main",
        ],
    },
)