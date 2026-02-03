"""Setup script for MAP.Py package."""

from setuptools import setup, find_packages

setup(
    name='map-py',
    version='0.2.0',
    description='Scope-aware recon + enumeration orchestrator for Kali',
    author='trace-rich413',
    packages=find_packages(),
    install_requires=[
        'pyyaml>=5.4',
    ],
    entry_points={
        'console_scripts': [
            'mappy=map_py.cli:main',
        ],
    },
    python_requires='>=3.7',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
)