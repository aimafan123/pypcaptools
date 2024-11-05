from setuptools import setup, find_packages

setup(
    name="pypcaptools",
    version="1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "dpkt==1.9.8",
        "scapy==2.6.0",
    ],
    entry_points={
        "console_scripts": [
            "pypcaptools.split_flow=pypcaptools.splitter:split_flow",
        ],
    },
    author="ZGC-BUPT-aimafan",
    author_email="chongrufan@nuaa.edu.cn",
    description="将pcap文件按照session或者flow进行分隔",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/ZGC-BUPT-aimafan/flowsplit.git",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
    python_requires=">=3.8",
)