control "V-89583" do
  title "User passwords must be changed at least every 60 days."
  desc  "Any password, no matter how complex, can eventually be cracked.
Therefore, passwords need to be changed periodically. If the operating system
does not limit the lifetime of passwords and force users to change their
passwords, there is the risk that the operating system passwords could be
compromised."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000076-GPOS-00044"
  tag "gid": "V-89583"
  tag "rid": "SV-100233r1_rule"
  tag "stig_id": "VRAU-SL-000395"
  tag "fix_id": "F-96325r1_fix"
  tag "cci": ["CCI-000199"]
  tag "nist": ["IA-5 (1) (d)", "Rev_4"]
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
  tag "check": "Check the max days field of /etc/shadow by running the
following command:

# cat /etc/shadow | cut -d':' -f1,5 | egrep -v \"([0|60])\" | grep -v \":$\"

If any results are returned, this is a finding."
  tag "fix": "Set the maximum time period between password changes for each
[USER] account to \"60\" days. The command in the check text will give you a
list of users that need to be updated to be in compliance.

# passwd -x 60 [USER]

The DoD requirement is \"60\" days."
end

