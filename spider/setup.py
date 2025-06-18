from setuptools import setup, find_packages

setup(
    name="web-spider",
    version="1.0.0",
    author="TraceVoid",
    description="Herramienta de reconocimiento web avanzada",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/TraceVoid/recon-spider",
    packages=find_packages(),
    install_requires=[
        'requests',
        'beautifulsoup4',
        'graphviz',
        'dnspython',
        'tqdm'
    ],
    entry_points={
        'console_scripts': [
            'webspider=spider.main:main'
        ],
    },
    python_requires='>=3.7',
)
