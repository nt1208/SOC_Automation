# SOC Automation Project
***
This is my personal project about Security Operation Center (SOC) providing a solution to help SOC analyst get alerts about the anomaly activities happening in their agents automatically.

### Components
- Wazuh (Server, Indexer, Dashboard): 35.187.244.131
- Windows Agent: 20.189.116.194
- Ubuntu Agent: 34.87.141.84
- Shuffle
- Virustotal

The flowchart below illustrates how these components can work with each other.

<img src="image/image1.png" height=450>

### Configuration
**Wazuh (Server, Indexer, Dashboard):**
+ Ubuntu 22.04.01
+ Internal IP: 10.148.0.3
+ External IP: 35.187.244.131

**Windows Agent**
+ Windows 10 Pro
+ Internal IP: 10.0.0.4
+ External IP: 20.189.116.194

**Ubuntu Agent**
+ Ubuntu 22.04.01
+ Internal IP: 10.148.0.4
+ External IP: 34.87.141.84

In wazuh manager, edit `config.yml` file with this following information. Consequently, both 3 components have same IP address.

<img src='image/image2.png' height=250>

After installing wazuh manager, we have some credentials containing in `wazuh-passwords.txt` file which can use to log in wazuh dashboard.

Then, we need to add agents (Windows and Ubuntu) which can be tracked by server. Going to wazuh dashboard and `Endpoints` sections then, select `Deploy new agents` and follow the instructions in this page. The picture below is the configuration for Ubuntu Agent, similar steps apply to the Windows Agent as well.

<img src='image/image3.png' height=400>

If we add our agents successfully, we can view it in `Endpoints` section.

<img src='image/image4.png' height=150>

Note that we need to edit server address value to our server in Windows Agent.

<img src='image/image5.png' height=200>

#### Windows Agent
In Windows Agent, we need to install **Sysmon**, which can monitor and log events to `Windows Event Log`. We can install it through this <a href="https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon">Link</a>.

After that, we need to add some information in `ossec.conf` to take `Sysmon` work with wazuh agent. 

<img src='image/image6.png' height=100>

The `location` value is a path which we can find it in `Windows Event Log`.

<img src='image/image7.png' height=300>


Because we need to test the status of wazuh agent wheather it work perfectly, i try to build some scenarios which mentioned later, therefore, we need to install **Mimikatz** and **Apache2** for this purpose. We can install **Mimikatz** from <a href="https://github.com/gentilkiwi/mimikatz/releases">Github</a> and **Apache2** with this <a href="https://documentation.wazuh.com/current/proof-of-concept-guide/block-malicious-actor-ip-reputation.html">instruction</a>.

<img src='image/image8.png' height=200>

<img src='image/image9.png' height=200>

Add the following to C:\Program Files (x86)\ossec-agent\ossec.conf to configure the Wazuh agent and monitor the Apache access logs:

<img src='image/image10.png' height=100>



#### Ubuntu Agent
We also need to install Apache2 on Ubuntu Agent. Use `sudo apt install apache2` and `systemctl start apache2` to install and run Apache service.

<img src='image/image11.png' height=300>

#### Scenarios
I try to build 4 scenarios for each Ubuntu and Windows agent:
**For Ubuntu Agent:**
+ SQL injection
+ File integrity
+ Brute-force attack
+ Shellshock atack

**For Windows Agent:**
+ SQL injection
+ File Integrity
+ Brute-force attack
+ Malicious actors

