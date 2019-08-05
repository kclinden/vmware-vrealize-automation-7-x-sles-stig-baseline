control "V-89851" do
  title "The SLES for vRealize audit system must be configured to audit file
deletions."
  desc  "If the system is not configured to audit certain activities and write
them to an audit log, it is more difficult to detect and track system
compromises and damages incurred during a system compromise."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000474-GPOS-00219"
  tag "gid": "V-89851"
  tag "rid": "SV-100501r1_rule"
  tag "stig_id": "VRAU-SL-001465"
  tag "fix_id": "F-96593r1_fix"
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
  tag "check": "Check the system audit configuration to determine if file and
directory deletions are audited:

# cat /etc/audit.rules /etc/audit/audit.rules | grep -e \"-a exit,always\" | grep -i \"rmdir\"

If no results are returned, or the results do not contain \"-S rmdir\", this is
a finding."
  tag "fix": "Add the following to \"/etc/audit/audit.rules\" in order to
capture file and directory deletion events:

-a always,exit -F arch=b64 -S rmdir -S rm
-a always,exit -F arch=b32 -S rmdir -S rm"

describe file('/etc/audit/audit.rules') do
  its('content') {should match %r{-a exit,always -F arch=b64 -S rmdir}} #modified, but not 100% sure this is a valid match.
  its('content') {should match %r{-a exit,always -F arch=b32 -S rmdir}}
end

end

