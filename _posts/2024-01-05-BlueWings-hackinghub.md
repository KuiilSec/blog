### BlueWings - HackingHub

I recently completed the **BlueWings** hub on [hackinghub](https://www.hackinghub.io/) and decided to post a writeup about it as I used these misconfigurations multiple times on multiple bug bounty targets and during several penetration tests.

> BlueWings is an innovative energy drink designed to keep hackers energized and focused late into the night! However, there has been a misconfiguration, leaving two Tomcat servers exposed, with one of them running Jolokia.

_Scope:_
- *.fh23w51c.bluewings.ctfio.com

Upon browsing to http://fh23w51c.bluewings.ctfio.com/, we see the following page. 

![](/blog/assets/images/BlueWings.png)

Upon looking in BurpSuite, we see the Server header indicating `nginx/1.18.0 (Ubuntu)`

![](/blog/assets/images/Server.png)

Upon inspecting the functionality on the website, we find a link to **Staff Login** which links to http://fh23w51c.bluewings.ctfio.com/staff. Upon visiting this, we are greeted with the following page.

![](/blog/assets/images/Staff.png)

This presents us some kind of login panel. After trying to access directories that may behind the login panel such as `/staff/members`, we are greeted with a 404-page that reveals the Tomcat version, namely `9.0.82`. 

![](/blog/assets/images/TomcatVersion.png)

Note that this also could have been detected by using [this](https://github.com/projectdiscovery/nuclei-templates/blob/dd7467687f546e22044edbe58bd22e5f912f7356/http/technologies/apache/tomcat-detect.yaml) Nuclei template.

![](/blog/assets/images/NucleiTCVersion.png)

Since this is Tomcat, a well-known way to get remote code execution is by uploading a malicious `.war` file in the Tomcat Manager interface (often exposed at `/manager/html`). But since only the requests to the `/staff/` directory seem to be handled by Tomcat, we have to traverse directories in order to be able to reach `/manager/html`. Upon reading [HackTricks' Tomcat page](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat), I noticed a path traversal chapter. It stated the following: 

> In some vulnerable configurations of Tomcat you can gain access to protected directories in Tomcat using the path: `/..;/` 

Web servers and reverse proxies normalize the request path. For example, the path **/image/../image/** is normalized to **/images/**. When Apache Tomcat is used together with a reverse proxy such as nginx (as is the case here) there potentially is a normalization inconsistency. Tomcat will threat the sequence **/..;/** as **/../** and normalize the path while reverse proxies will not normalize this sequence and send it to Apache Tomcat as it is. This allows an attacker to access Apache Tomcat resources that are not normally accessible via the reverse proxy mapping. This can remediated by configuring the reverse proxy to reject paths that contain the Tomcat path parameter character `;`.

This can also be identified using [this](https://github.com/projectdiscovery/nuclei-templates/blob/dd7467687f546e22044edbe58bd22e5f912f7356/http/misconfiguration/apache/tomcat-pathnormalization.yaml) Nuclei template.

![](/blog/assets/images/PathNorma.png)

The next step is trying to access the manager interface by going to http://fh23w51c.bluewings.ctfio.com/staff/..;/manager/html. As shown in the image below, this appears to be working as we are greeted with a login dialog.

![](/blog/assets/images/BasicAuth.png)

I then wrote the following Python script that tried the default credentials listed by HackTricks' Tomcat page.

```python
import base64
import requests
import sys


def do_login(username, password):
    url = "http://7kjo02z1.bluewings.ctfio.com:80/staff/..;/manager/html"

    basic_auth = f"{username}:{password}"
    b64_basic_auth = base64.b64encode(basic_auth.encode("utf-8")).decode()

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1",
        "Authorization": f"Basic {b64_basic_auth}"
    }

    r = requests.get(url, headers=headers)

    if r.status_code != 401:
        print(f"[+] Logged in Successfully with username: {username} and password: {password}")
        sys.exit()
    else:
        print(f"[!] Log in failed with username: {username} and password: {password}")


def main():
    usernames = ["admin", "tomcat", "tomcatgui"]
    passwords = ["admin", "", "tomcat", "s3cr3t"]

    for username in usernames:
        for password in passwords:
            do_login(username, password)

  
if __name__ == "__main__":
    main()
```

But unfortunately, none of the default credentials seemed to be working.

![](/blog/assets/images/Brute.png)

I then resorted to enumerating web directories using [ffuf](https://github.com/ffuf/ffuf).  I personally used `quickhits.txt` from [SecLists](https://github.com/danielmiessler/SecLists/blob/42eb03287271864092c720bb7f11dcddecfb58dd/Discovery/Web-Content/quickhits.txt#L4)

```bash
ffuf -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0" -w quickhits.txt -u http://fh23w51c.bluewings.ctfio.com:80/staff/..\;/FUZZ
```

This revealed a new, and potentially interesting, web directory named _jolokia_. 

![](/blog/assets/images/ffuf.png)

Upon inspecting this, I got the following response, which is a typical response for **Jolokia**:

> Jolokia is a JMX-HTTP bridge giving an alternative to JSR-160 connectors. It is an agent based approach with support for many platforms. In addition to basic JMX operations it enhances JMX remoting with unique features like bulk requests and fine grained security policies.

![](/blog/assets/images/jolokia.png)

Upon Googling for vulnerabilities related to Jolokia, I bumped into the [Jolokia Exploitation Toolkit](https://github.com/laluka/jolokia-exploitation-toolkit). This contained a folder named _exploits_, which contained descriptions and proof of concepts of Exploits against Jolokia. I tried [the first one](https://github.com/laluka/jolokia-exploitation-toolkit/blob/main/exploits/file-read-compilerdirectivesadd.md) which tries to load a new compiler directive. The result will be a "Bad format for file X" error message, while the content is included in this error message. Using this, I was able to read the _/etc/passwd_ file.

![](/blog/assets/images/passwd.png)

Notice that this could also be verified using the following [Nuclei template](https://github.com/projectdiscovery/nuclei-templates/blob/dd7467687f546e22044edbe58bd22e5f912f7356/http/misconfiguration/jolokia/jolokia-unauthenticated-lfi.yaml#L4).

![](/blog/assets/images/ncl.png)

Although reading _/etc/passwd_ is nice, our goal is to gain a shell on the hackinghub. Since we are able to reach _/manager/html_ via the _/..;/_ sequence, we can try and read the _tomcat-users.xml_ file. This file is known for containing roles, usernames and passwords for Tomcat users. 

But since we do not know the exact location of this file, I decided to pull a Tomcat Docker image to inspect the filesystem.

![](/blog/assets/images/docker.png)

After pulling the image, we start a container running our Tomcat instance.

![](/blog/assets/images/docker2.png)

We then list all Docker containers to identify our Tomcat container, and gain a root shell into it by executing the following command:

```bash
docker exec -it <CONTAINER ID> bash
```

After doing this, we land in the _/usr/local/tomcat_ directory. Doing a `ls` reveals the **conf** directory which contains our target, namely _tomcat-users.xml_. 

![](/blog/assets/images/docker3.png)

We can then try reading this file using the Jolokia exploit we identified earlier. Which appears to be working as we get the xml file containing usernames and passwords back.

![](/blog/assets/images/tcu.png)

With the exposed password for _tomcatgui_, I was able to login to the Tomcat Manager.

![](/blog/assets/images/manager.png)

A known way to get command execution is by uploading a malicious WAR file in the Tomcat manager. I decided to create a WAR file containing a [webshell](https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp). 

![](/blog/assets/images/wshell.png)

If we try uploading the webshell directly from the manager interface, we get an error. If we intercept this request with Burpsuite, we quickly identify the problem. The upload points to _/manager/html_, while we need to use our _/..;/_ sequence to reach the manager.

![](/blog/assets/images/notworking.png)

So we need to update the request path to look like the following.

![](/blog/assets/images/fix.png)

After doing this, our malicious WAR file gets uploaded successfully.

![](/blog/assets/images/uploaded.png)

We can then browse to it, and use it to execute commands. It appears that this Tomcat instance is running as root, meaning we completely compromised this hackinghub.

![](/blog/assets/images/rce.png)