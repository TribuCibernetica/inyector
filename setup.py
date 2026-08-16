from setuptools import setup, find_packages

setup(
    name="inyector",
    version="1.0.0",
    packages=find_packages(),
    # Mantener sincronizado con requirements.txt — este archivo es lo
    # que se usa si alguien instala fuera de Docker (pip install -e .).
    install_requires=[
        "click==8.3.3",
        "requests==2.33.0",
        "httpx==0.28.1",
        "beautifulsoup4==4.12.3",
        "rich==13.7.0",
        "jinja2==3.1.6",
        "python-whois==0.9.4",
        "dnspython==2.6.1",
        "websocket-client==1.7.0",
        "urllib3==2.7.0",
        "fake-useragent==1.5.1",
        "colorama==0.4.6",
        "pydantic==2.13.4",
        "brotli==1.2.0",
        "google-genai==2.18.0",
    ],
    entry_points={
        "console_scripts": [
            "inyector=inyector.cli:main",
        ],
    },
)
