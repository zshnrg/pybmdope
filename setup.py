from setuptools import setup, find_packages

setup(
    name="py-bmdope",
    version="0.0.1",
    author="Rozan Ghosani",
    author_email="ghosanirozan1@gmail.com",
    description="A Block Metadata-Driven Order-Preserving Encryption (BMDOPE)",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/zshnrg/py-bmdope",
    packages=find_packages(where="bmdope"),
    package_dir={"": "bmdope"},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
    ],
)
