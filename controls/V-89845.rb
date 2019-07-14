control "V-89845" do
  title "The SLES for vRealize audit system must be configured to audit failed
attempts to access files and programs."
  desc  "Unsuccessful attempts to access files could be an indicator of
malicious activity on a system. Auditing these events could serve as evidence
of potential system compromise."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000474-GPOS-00219"
  tag "gid": "V-89845"
  tag "rid": "SV-100495r1_rule"
  tag "stig_id": "VRAU-SL-001440"
  tag "fix_id": "F-96587r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Verify auditd is configured to audit failed file access
attempts. There must be both an \"-F exit=-EPERM\" and \"-F exit=-EACCES\" for
each access syscall:

# cat /etc/audit.rules /etc/audit/audit.rules | grep -e \"-a exit,always\" |
grep -e \"-S open\" | grep -e \"-F exit=-EPERM\"

# cat /etc/audit.rules /etc/audit/audit.rules | grep -e \"-a exit,always\" |
grep -e \"-S open\" | grep -e \"-F exit=-EACCES\"

There must be both an \"-F exit=-EPERM\" and \"-F exit=-EACCES\" for each
access syscall.

If not, this is a finding."
  tag "fix": "Edit the audit.rules file and add the following line(s) to enable
auditing of failed attempts to access files and programs:

-a exit,always -F arch=b64 -S open -F exit=-EPERM
-a exit,always -F arch=b64 -S open -F exit=-EACCES
-a exit,always -F arch=b32 -S open -F exit=-EPERM
-a exit,always -F arch=b32 -S open -F exit=-EACCES"
end

