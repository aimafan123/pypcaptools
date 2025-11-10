from setuptools import find_packages, setup

setup(
    name="pypcaptools",
    version="2.3",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=["dpkt==1.9.8", "scapy==2.6.0", "mysql-connector-python==9.1.0"],
    author="aimafan123",
    author_email="chongrufan@nuaa.edu.cn",
    description="一个用于解析pcap文件的python库",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/aimafan123/pypcaptools.git",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
    python_requires=">=3.8",
)
