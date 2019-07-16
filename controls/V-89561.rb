control "V-89561" do
  title "The SLES for vRealize must generate audit records when
successful/unsuccessful attempts to access privileges occur. The SLES for
vRealize must generate audit records for all failed attempts to access files
and programs."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000064-GPOS-00033"
  tag "gid": "V-89561"
  tag "rid": "SV-100211r1_rule"
  tag "stig_id": "VRAU-SL-000320"
  tag "fix_id": "F-96303r1_fix"
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
  tag "check": "To check that the audit system collects unauthorized file
accesses, run the following commands:

# grep EACCES /etc/audit/audit.rules

-a exit,always -F arch=b64 -S swapon -F exit=-EACCES
-a exit,always -F arch=b64 -S creat -F exit=-EACCES
-a exit,always -F arch=b64 -S open -F exit=-EACCES

# grep EPERM /etc/audit/audit.rules

-a exit,always -F arch=b64 -S swapon -F exit=-EPERM
-a exit,always -F arch=b64 -S creat -F exit=-EPERM
-a exit,always -F arch=b64 -S open -F exit=-EPERM

If either command lacks output, this is a finding."
  tag "fix": "Add the following to \"/etc/audit/audit.rules\":

-a exit,always -F arch=b64 -S swapon -F exit=-EACCES
-a exit,always -F arch=b64 -S creat -F exit=-EACCES
-a exit,always -F arch=b64 -S open -F exit=-EACCES

-a exit,always -F arch=b64 -S swapon -F exit=-EPERM
-a exit,always -F arch=b64 -S creat -F exit=-EPERM
-a exit,always -F arch=b64 -S open -F exit=-EPERM

Or run the following command to implement all logging requirements:

# /etc/dodscript.sh"

describe file("/etc/audit/audit.rules") do
  its("content") { should match %r{-a exit,always -F arch=b64 -S swapon -F exit=-EACCES} }
  its("content") { should match %r{-a exit,always -F arch=b64 -S creat -F exit=-EACCES} }
  its("content") { should match %r{-a exit,always -F arch=b64 -S open -F exit=-EACCES} }
  its("content") { should match %r{-a exit,always -F arch=b64 -S swapon -F exit=-EPERM} }
  its("content") { should match %r{-a exit,always -F arch=b64 -S creat -F exit=-EPERM} }
  its("content") { should match %r{-a exit,always -F arch=b64 -S open -F exit=-EPERM} }
end

end

