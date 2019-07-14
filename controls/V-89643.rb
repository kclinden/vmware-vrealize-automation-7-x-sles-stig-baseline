control "V-89643" do
  title "The alias files must be owned by root."
  desc  "If the alias and aliases.db files are not owned by root, an
unauthorized user may modify the file to add aliases to run malicious code or
redirect email."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89643"
  tag "rid": "SV-100293r1_rule"
  tag "stig_id": "VRAU-SL-000560"
  tag "fix_id": "F-96385r1_fix"
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
  tag "check": "Check the ownership of the alias file:

# ls -lL /etc/aliases
# ls -lL /etc/aliases.db

If all the files are not owned by \"root\", this is a finding."
  tag "fix": "Change the owner of the alias files to \"root\":

# chown root /etc/aliases
# chown root /etc/aliases.db"
end

