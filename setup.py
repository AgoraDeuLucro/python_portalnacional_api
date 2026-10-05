from setuptools import setup

with open("README.md", "r", encoding="utf-8") as arq:
    readme = arq.read()

setup(
    name="py_portalnacional",
    version="0.1.0",
    license="MIT License",
    author="Yuri Gomes",
    long_description=readme,
    long_description_content_type="text/markdown",
    author_email="yurialdegomes@gmail.com",
    keywords="nfse portal nacional nfs-e adn sefin",
    description="Wrapper não oficial das APIs do Portal Nacional de NFS-e",
    packages=["py_portalnacional"],
    install_requires=["requests", "cryptography"],
    python_requires=">=3.10",
)
