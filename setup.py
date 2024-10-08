from setuptools import setup, find_packages


setup(
    name="Lyer",
    version="0.0.1",
    packages=find_packages(),
    install_requires=[
        "pycryptodome",
        "mysql-connector-python"
    ],
    author="0lunar",
    author_email="LunarStone292@proton.me",
    description="File transfer library",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/0lunar/lyer",
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
)