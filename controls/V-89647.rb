control "V-89647" do
  title "The alias files must have mode 0644 or less permissive."
  desc  "Excessive permissions on the alias files may permit unauthorized
modification. If an alias file is modified by an unauthorized user, they may
modify the file to run malicious code or redirect email."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89647"
  tag "rid": "SV-100297r1_rule"
  tag "stig_id": "VRAU-SL-000570"
  tag "fix_id": "F-96389r1_fix"
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
  tag "check": "Check the permissions of the alias files:

# ls -lL /etc/aliases
# ls -lL /etc/aliases.db

If the files have a mode more permissive than \"0644\", this is a finding."
  tag "fix": "Change the mode of the alias files to \"0644\":

# chmod 0644 /etc/aliases /etc/aliases.db"

describe file('/etc/aliases') do
  it { should_not be_more_permissive_than('0644') }
end

describe file('/etc/aliases.db') do
  it { should_not be_more_permissive_than('0644') }
end

end

