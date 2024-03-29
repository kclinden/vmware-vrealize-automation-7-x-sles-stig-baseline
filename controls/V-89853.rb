control "V-89853" do
  title "SLES for vRealize audit logs must be rotated daily."
  desc  "Rotate audit logs daily to preserve audit file system space and to
conform to the DISA requirement. If it is not rotated daily and moved to
another location, then there is more of a chance for the compromise of audit
data by malicious users."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000474-GPOS-00219"
  tag "gid": "V-89853"
  tag "rid": "SV-100503r1_rule"
  tag "stig_id": "VRAU-SL-001470"
  tag "fix_id": "F-96595r1_fix"
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
  tag "check": "Check for a \"logrotate\" entry that rotates audit logs.

# ls -l /etc/logrotate.d/audit

If it exists, check for the presence of the \"daily\" rotate flag:

# egrep \"daily\" /etc/logrotate.d/audit

The command should produce a \"daily\" entry in the logrotate file for the
audit daemon.

If the \"daily\" entry is missing, this is a finding."
  tag "fix": "Create or edit the /etc/logrotate.d/audit file and add the
\"daily\" entry, such as:

/var/log/audit/audit.log {
compress
dateext
rotate 15
daily
missingok
notifempty
create 600 root root
sharedscripts
postrotate
/sbin/service auditd restart 2> /dev/null > /dev/null || true
endscript
}"

describe file('/etc/logrotate.d/audit') do
  its('content') {should cmp %r{daily}}
end

end

