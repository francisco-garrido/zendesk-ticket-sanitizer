Security Fixes and Changes for Zendesk Ticket Sanitizer

1. B404 - Blacklisted subprocess Module
   Description: The original code used the subprocess module to download the spaCy model automatically, which posed a potential security risk.

Fix: Removed all usage of subprocess. Now, the code provides clear error messages instructing the user to manually install the necessary dependencies.

Why: This eliminates the risk of command injection and improves the security posture by following the principle of least privilege.

2. B607 - Partial Executable Path
   Description: The script was using a partial executable path (subprocess.run(["python", ...])), which could have led to a "path hijacking" vulnerability.

Fix: The subprocess call was entirely removed, and manual installation of dependencies is now required by the user.

Why: By removing the subprocess call, we ensure that no external processes are executed, thus eliminating the path hijacking risk.

3. B603 - subprocess Without shell=True
   Description: The use of subprocess.run() without the shell=True flag was flagged for potential security risks, even though shell=True would have introduced more dangers.

Fix: The subprocess module was entirely removed, and error handling was added to provide guidance to users.

Why: This completely removes the possibility of command injection, as no shell commands are executed.
