control "V-89847" do
  title "The SLES for vRealize audit system must be configured to audit failed
attempts to access files and programs."
  desc  "Unsuccessful attempts to access files could be an indicator of
malicious activity on a system. Auditing these events could serve as evidence
of potential system compromise."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000474-GPOS-00219"
  tag "gid": "V-89847"
  tag "rid": "SV-100497r1_rule"
  tag "stig_id": "VRAU-SL-001455"
  tag "fix_id": "F-96589r1_fix"
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
attempts.

# cat /etc/audit.rules /etc/audit/audit.rules | grep -e \"-a exit,always\" |
grep -e \"-S ftruncate\" | grep -e \"-F success=0\"

There must be an audit rule for each of the access syscalls logging all failed
accesses (-F success=0).

If not, this is a finding."
  tag "fix": "Edit the audit.rules file and add the following line(s) to enable
auditing of failed attempts to access files and programs:

-a exit,always -F arch=b64 -S ftruncate -F success=0
-a exit,always -F arch=b32 -S ftruncate -F success=0"
end

