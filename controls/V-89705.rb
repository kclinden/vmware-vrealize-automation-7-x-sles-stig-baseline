control "V-89705" do
  title "All GIDs referenced in /etc/passwd must be defined in /etc/group."
  desc  "Inconsistency in GIDs between /etc/passwd and /etc/group could lead to
a user having unintended rights."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000121-GPOS-00062"
  tag "gid": "V-89705"
  tag "rid": "SV-100355r1_rule"
  tag "stig_id": "VRAU-SL-000740"
  tag "fix_id": "F-96447r1_fix"
  tag "cci": ["CCI-000804"]
  tag "nist": ["IA-8", "Rev_4"]
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
  tag "check": "To ensure all GIDs referenced in /etc/passwd are defined in
/etc/group, run the following command:

# pwck -rq

If a line is returned, this is a finding."
  tag "fix": "Add a group to the system for each GID referenced without a
corresponding group."
end

