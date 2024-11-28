# Cryptography-Legal-Industry
An Internet Security &amp; Privacy project that employs cryptography to solve an issue in the legal industry

Step 1:

Let liboqs-python install liboqs automatically
If liboqs is not detected at runtime by liboqs-python, it will be downloaded, configured and installed automatically (as a shared library). This process will be performed only once, at runtime, i.e., when loading the liboqs-python wrapper. The liboqs source directory will be automatically removed at the end of the process.

This is convenient in case you want to avoid installing liboqs manually, as described in the subsection above.

Install and activate a Python virtual environment
Execute in a Terminal/Console/Administrator Command Prompt

python3 -m venv venv
. venv/bin/activate
python3 -m ensurepip --upgrade
On Windows, replace the line

. venv/bin/activate
by

venv\Scripts\activate.bat
Configure and install the wrapper
Execute in a Terminal/Console/Administrator Command Prompt

git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python
pip install .

Step 2:

pip install -r requirements.txt

for any additional libraries.

Step 3:

Download GPG for enc_dec.py : https://www.gpg4win.org/get-gpg4win.html
