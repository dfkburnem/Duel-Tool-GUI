from setuptools import setup, find_packages

setup(
    name='duel_app_gui',
    version='2.0.0',  
    packages=find_packages(),  
    py_modules=['duel_app_gui'],
    install_requires=[
        'cryptography>=40.0.2',
        'web3>=6.4.0',
    ],
    entry_points={
        'console_scripts': [
            'duel_app_gui=duel_app_gui:main',
        ],
    },
    author='burnem',  
    author_email='dfkburnem@gmail.com',  
    description='A GUI for automating duels in DFK',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/dfkburnem/Duel-Tool-GUI',  
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Microsoft :: Windows',
    ],
    python_requires='>=3.6,<4',
)
