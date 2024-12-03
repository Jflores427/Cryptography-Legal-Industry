# Cryptography-Legal-Industry

### An Internet Security &amp; Privacy project that employs cryptography to solve  confidentiality, authenticity, and integrity issues within the legal industry.


## Prerequisites
- [Git](https://git-scm.com/)
- [liboqs](https://github.com/open-quantum-safe/liboqs)
- [Python 3](https://www.python.org/)
- [GPG](https://www.gnupg.org/download/)

## Step 1:

Let liboqs-python install liboqs automatically
If liboqs is not detected at runtime by liboqs-python, it will be downloaded, configured and installed automatically (as a shared library). This process will be performed only once, at runtime, i.e., when loading the liboqs-python wrapper. The liboqs source directory will be automatically removed at the end of the process.

This is convenient in case you want to avoid installing liboqs manually, as described in the subsection above.

Install and activate a Python virtual environment
Execute in a Terminal/Console/Administrator Command Prompt

```
python3 -m venv venv
. venv/bin/activate
python3 -m ensurepip --upgrade
```

On Windows, replace the line
```
. venv/bin/activate
```
by
```
venv\Scripts\activate.bat
```

Let liboqs-python install liboqs automatically by configuring and installing the wrapper
Execute in a Terminal/Console/Administrator Command Prompt
```
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python
pip install .
```
## Step 2:
```
cd ../
pip install -r requirements.txt
```
to install any additional dependencies.

## Step 3:

Ensure your GPG keybox daemon/GPG agent is running in the background and execute 
```
python main.py
```
for a demo of the available features within this project.

### Contributors

Contributors include:

- Cris Cortes
- Eileen Xu
- Josue Flores
- Lakshmi Raj
- Yukta Kalkarni
