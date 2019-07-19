control "V-89607" do
  title "The telnet-server package must not be installed."
  desc  "Removing the \"telnet-server\" package decreases the risk of the
unencrypted telnet service's accidental (or intentional) activation."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000095-GPOS-00049"
  tag "gid": "V-89607"
  tag "rid": "SV-100257r1_rule"
  tag "stig_id": "VRAU-SL-000460"
  tag "fix_id": "F-96349r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
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
  tag "check": "Check if \"telnet-server\" is installed:

# rpm -q telnet-server

If there is a \"telnet-server\" package listed, this is a finding."
  tag "fix": "To remove the \"telnet-server\" package use the following command:

rpm -e telnet-server"

describe package('telnet-server') do
  it { should_not be_installed }
end

end

