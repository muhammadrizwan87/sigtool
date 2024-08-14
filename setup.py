from setuptools import setup, find_packages

setup(
    name='sigtool',
    version='1.0',
    description='A tool for analyzing signatures of APK files',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='MuhammadRizwan',
    author_email='mrizwan87@protonmail.com',
    url='https://github.com/muhammadrizwan87/sigtool',
    license='MIT',
    packages=find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
    install_requires=[],
    entry_points={
        'console_scripts': [
            'sigtool=sigtool.main:main',
        ],
    },
)