control "V-89631" do
  title "The xinetd.d directory must have mode 0755 or less permissive."
  desc  "The Internet service daemon configuration files must be protected as
malicious modification could cause denial of service or increase the attack
surface of the system."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89631"
  tag "rid": "SV-100281r1_rule"
  tag "stig_id": "VRAU-SL-000530"
  tag "fix_id": "F-96373r1_fix"
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
  tag "check": "Check the permissions of the \"xinetd\" configuration
directories:

# ls -dlL /etc/xinetd.d

If the mode of the directory is more permissive than \"0755\", this is a
finding."
  tag "fix": "Change the mode of the directory:

# chmod 0755 /etc/xinetd.d"

describe directory('/etc/xinetd.d') do
  it{should_not be_more_permissive_than '0755'}
end

end

