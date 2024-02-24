from setuptools import setup, find_packages

setup(
    name='rsa_key_info',
    version='24.02.24.2',
    description='Extracts information from a given public RSA key file.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='EfcyLab',
    author_email='efcyla@proton.me',
    url='https://github.com/efcylab/rsa_key_info',
    packages=find_packages(),
    install_requires=[
        'pyfiglet',
        'pycryptodome'
    ],
    entry_points={
        'console_scripts': [
            'rsa_key_info = rsa_key_info.main:main'
        ]
    },
)
