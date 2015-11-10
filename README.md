# kippo-pyshield
Script to send kippo/cowrie honeypot login attempt information to https://isc.sans.edu/ssh.html
It can read login attempts from kippo/cowrie log files, or from a MySQL database if your 
honeypot is redirecting its logs there too. 

Adapted from the Perl script published by isc.sans.edu at https://isc.sans.edu/clients/kippo/kippodshield.pl

## Installation

- Edit kipposhield.py and set the values for auth_key and dbshield_userid. Both can be
  found at your profile page at https://isc.sans.edu/myinfo.html
  If you plan to read login attempts from the DB, add the values for db_name, db_host, db_username, db_password

- Install dependencies 
  ```
  pip install requests tzlocal MySQL-python pytz
  ```
- Clone the repository
  ```
  git clone https://github.com/jkakavas/kippo-pyshield.git
  ```
- Make the script executable
  ```
  chmod +x kipposhield.py
  ```

## Usage
```
./kipposhield.py -h
usage: kipposhield.py [-h] [-db] [-f LOGFILE]

optional arguments:
-h, --help  show this help message and exit
-db         Get login attempts from a database
-f LOGFILE  Get login attemtps from a log file

```

kipposhield marks the timestamp of the last log entry it has sent to ICS in a
text file in the current directory in order to not send duplicate entries. If 
there is a need to bypass this, one can edit or remove the last_sent file from 
the current directory. 

### Example output

```
cowrie@mypot:~/kippo-pyshield$ ./kipposhield.py -f /home/cowrie/cowrie/log/cowrie.log.2
INFO: analyzing and sending entries that occured later than 2015-11-10 11:16:46
INFO: Found 2 login attempts in the specified log source
INFO: Sending all entries to the server
response is ok

SUCCESS: Sent 101 bytes worth of data to secure.dshield.org

```
