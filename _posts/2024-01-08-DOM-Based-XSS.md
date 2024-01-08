# DOM-Based Cross-Site Scripting (XSS) with CodeQL and/or DOM Invader

According to [PortSwigger](https://portswigger.net/web-security/cross-site-scripting/dom-based), "DOM-based XSS vulnerabilities usually arise when JavaScript takes data from an attacker-controllable source, such as the URL, and passes it to a sink that supports dynamic code execution, such as `eval()` or `innerHTML`. This enables attackers to execute malicious JavaScript, which typically allows them to hijack other users' accounts.

Identifying and exploiting DOM XSS on penetration tests and bug bounty targets can be a tedious process, often requiring you to analyze complex, minified JavaScript. PortSwigger developed a tool called [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader), which makes this process a lot easier (I will showcase this as well at the end of the blog). But I wanted to blog about another workflow that I personally use, namely [CodeQL](https://codeql.github.com/)

### CodeQL

CodeQL is a semantic code analysis engine developed by Github. It lets you query code as though it were data. It allows you to write custom queries to find all variants of a vulnerability, and then share it with others to help them do the same.

Since it supports queries for JavaScript, it can be used to find client-side vulnerabilties such as DOM-Based XSS. To showcase this, I created a simple HTML page.

```html
<!DOCTYPE html>
<html>
    <head>
    </head>
    <body>
        <script>
            var source = (new URLSearchParams(window.location.search)).get('bug');
            document.write('<h1>' + source + '</h1>');
        </script>
    </body>
</html>
```

To analyze this code, we need to download the [CodeQL-CLI](https://github.com/github/codeql-action/releases). After it is downloaded, extract the zip archive. Once extracted, you can run CodeQL processes by running the `codeql` executable in two ways:
- By executing `<extraction-root>/codeql/codeql`, where `<extraction-root>` is the folder where you extracted the CodeQL CLI package.
- By adding `<extraction-root>/codeql` to your `PATH`, so that you can run the executable as just `codeql`

After everything is set up correctly, we can start analyzing our files. First, we need to create a CodeQL database which will contain the data needed to analyze our code. This can be done by running the following command:

```bash
~/codeql/codeql database create <database-name> --language=javascript
```

After successfully creating the database, we can start running queries against the database with the following command:

```bash
~/codeql/codeql database analyze <database-name> --format=CSV --output=<FILENAME>.csv
```

This will place the results in CSV format in a file named `<FILENAME>.csv`. After the command finishes, we can simply inspect this file to see if CodeQL found anything. As shown in the screenshot below, CodeQL successfully identified the DOM-Based XSS vulnerability.

![](/blog/assets/images/CQL-Results.PNG)

While this demonstrates the usage and viability of CodeQL for identifying these kind of issues, it does not really demonstrate how this could be used on real-life targets. So let's see how this would apply to real-life targets. First, I personnaly use an extension in Google Chrome named [Save All Resources](https://chromewebstore.google.com/detail/save-all-resources/abpdnfjocnmdomablahdcfnoggeeiedb?pli=1). This extension downloads all resources with while retaining the folder structure. Let's showcase this against the [DOM XSS in PortSwigger's document.write sink using source location.source lab](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink).

I launched the lab instance, and then browsed the functionality. After I explored all the functionality, I went to Chrome DevTools and navigated to _ResourcesSaver_, which allows us to _Save All Resources_.

![](/blog/assets/images/ResourceSaver.PNG)

This will download a zip archive containing all the resources. We can extract this zip archive and build a CodeQL database for it.

![](/blog/assets/images/PortSwiggerCQLDBCreate.PNG)

After successfully creating the database, we can analyze it.

![](/blog/assets/images/PortswiggerCQLAnalysis.PNG)

Once CodeQL is done analyzing, we can inspect the created _csv_ file to see the results.

![](/blog/assets/images/PortswiggerResults.PNG)

Notice that CodeQL also points us in the right direction for the DOM-Based XSS vulnerability present in the lab, which is detailed in the image below

![](/blog/assets/images/PortswiggerVulnCode.PNG)

Using this information, we can easily create a proof of concept for this vulnerability. We need to close the src attribute using a `"`, and can then close the image tag using `>`. We are then able to inject arbitrary tags, so we can simply use `r_vd_l"><img src=x onerror=prompt()>` as a proof of concept: 

![](/blog/assets/images/PortswiggerPrompt.PNG)

### DOM Invader

As mentioned at the beginning of this blogpost, PortSwigger developed a browser extension (available on Burpsuite's built-in web browser) named DOM Invader. This extension makes testing for DOM-Based XSS vulnerabilities quite a bit easier. Let me demonstrate it on the same lab as before. If you are following along, make sure DOM Invader is turned on.

DOM Invader uses a _canary_, which can be copied into parameters, input field, etc. DOM Invader then checks if this canary ends up in interesting sinks. If an interesting sink is found, this will be shown in the DOM Invader tab of the Developer Tools. If we copy our canary into the search parameter, we see that DOM Invader shows a red `1`, and indicates us that our canary ended up in a `document.write` sink. 

![](/blog/assets/images/DomInvader.PNG)

DOM Invader contains an _Exploit_ button for some _"findings"_, but in my opinion it does not work in every case. So I generally click at the hyperlink underneath _Stack Trace_.

![](/blog/assets/images/Stack.PNG)

After clicking this, you need to open the _console_ (tab in Developer Tools) to view the stack trace.

![](/blog/assets/images/StackTrace.PNG)

By clicking on the hyperlinks, we are taken to the code that contains the DOM-Based XSS vulnerability.

![](/blog/assets/images/vulncode.PNG)

This would allow us to construct the same proof of concept as in the CodeQL chapter.