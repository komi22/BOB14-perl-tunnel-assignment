# BOB14-perl-tunnel-assignment
The following code was developed for this assignment:
<https://github.com/JaewookYou/bob-perl-tunnel-assignment>

This implementation is intended only for the provided Docker lab and authorized testing. Do not use it outside a controlled environment.

## Usage
### 1) Change URL
Open `run.py` and change BASE_DEFAULT to your image’s web server URL (the one that serves `upload.jsp` / `download.jsp`):
```python
# run.py
BASE_DEFAULT = "http://192.168.183.128:8080"
```

## 2) Run
```python run.py```

## Preview 
```
PS C:\Users\User\test\BOB14-perl-tunnel-assignment-main> python run.py
[+] uploaded 5210 hex chars into uploads/agentx
[check] agent.pl HTTP=200 size=2605
[probe uploads] 200 'OK'
[bootstrap ok] True
[+] SOCKS5 (one-shot) on 127.0.0.1:1080  autoget=True  open=False
[ready] SOCKS listening on 127.0.0.1:1080
[launch] Chrome started: C:\Program Files\Google\Chrome\Application\chrome.exe --user-data-dir=C:\Users\User\AppData\Local\Temp\ChromeSocks_gui_ok ... http://172.18.0.2:5000/
```
<!-- 480px -->
<img src="https://raw.githubusercontent.com/komi22/BOB14-perl-tunnel-assignment/main/Success.png" width="480" alt="Success">


## Auto Process

- Uploads and reconstructs agent.pl on the server (via filename CMDi with RFC 2047 Q-encoding).
- Starts the agent (perl agent.pl on the server).
- Launches a local SOCKS5 proxy (default 127.0.0.1:1080).
- (Optional) Auto-opens Chrome to http://172.18.0.2:5000/ (internal web app).
