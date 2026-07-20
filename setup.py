from setuptools import setup, find_packages

setup(
    name="inyector",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "click", "requests", "httpx", "rich",
        "beautifulsoup4", "jinja2", "fake-useragent",
        "pydantic",
    ],
    entry_points={
        "console_scripts": [
            "inyector=inyector.cli:main",
        ],
    },
)
