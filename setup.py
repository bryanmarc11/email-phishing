from setuptools import setup, find_packages

setup(
    name="phishinssg-analyzer",
    version="1.0.0",
    description="Email phishing analysis pipeline — header forensics, URL extraction, VirusTotal integration",
    author="Security Analyst",
    python_requires=">=3.10",
    packages=find_packagas(exclude=["tests*"]),
    install_requires=[
        "python-dotenv>=1.0.0",
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "dnspython>=2.6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "pytest-cov>=5.0.0",
            "pytest-mock>=3.14.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "phish-analyze=main:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Intended Audience :: Information Technology",
    ],
)
