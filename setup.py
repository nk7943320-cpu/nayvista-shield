from setuptools import setup, find_packages

setup(
    name="nayvista-shield",
    version="1.0.0",
    description="NayVista Shield - AI-Assisted Web Security Assessment",
    author="NayVista Technologies",
    packages=find_packages(),
    install_requires=[
        "httpx>=0.28.0",
        "beautifulsoup4>=4.13.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "shield=scanner.cli:main",
            "nayvista-shield=scanner.cli:main",
            "nshield=scanner.cli:main",
            "sentinelscan=scanner.cli:main",
        ],
    },
    python_requires=">=3.10",
)
