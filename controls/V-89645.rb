control "V-89645" do
  title "The alias files must be group-owned by root or a system group."
  desc  "If the aliases and aliases.db file are not group owned by root or a
system group, an unauthorized user may modify one or both of the files to add
aliases to run malicious code or redirect email."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89645"
  tag "rid": "SV-100295r1_rule"
  tag "stig_id": "VRAU-SL-000565"
  tag "fix_id": "F-96387r1_fix"
  tag "cci": ["CCI-000382"]
  tag "nist": ["CM-7 b", "Rev_4"]
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
  tag "check": "Check the group-ownership of the alias files:

# ls -lL /etc/aliases
# ls -lL /etc/aliases.db

If the files are not group-owned by \"root\", this is a finding."
  tag "fix": "Change the group-owner of the alias files to \"root\":

# chgrp root /etc/aliases
# chgrp root /etc/aliases.db"
end

