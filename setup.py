from setuptools import setup, find_packages

setup(
    name="grudarin",
    version="2.0.0",
    description="Network Spy & Intelligence Tool - Real-time behavioral surveillance",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Grudarin Contributors",
    license="GPL-3.0",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=["scapy>=2.5.0", "rich>=13.0.0"],
    entry_points={
        "console_scripts": ["grudarin=grudarin.__main__:main"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: GPL-3.0 License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
)
