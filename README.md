# kippo-pyshield
Script to send kippo/cowrie honeypot login attempt information to https://isc.sans.edu/ssh.html

Adapted from the Perl script published by isc.sans.edu at https://isc.sans.edu/clients/kippo/kippodshield.pl

## Installation

- Edit kipposhield.py and set the values for auth_key and dbshield_userid. Both can be
  found at your profile page at https://isc.sans.edu/myinfo.html
- Install requests 
  ```
  pip install requests
  ```
- Clone the repository
  ```
  git clone https://github.com/jkakavas/kippo-pyshield.git
  ```
- Make the script executable
  ```
  chmod +x kipposhield.py
  ```

# Usage
```
./kipposhield.py kippo.log
```
