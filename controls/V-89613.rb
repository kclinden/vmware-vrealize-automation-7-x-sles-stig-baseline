control "V-89613" do
  title "The yast2-tftp-server package must not be installed."
  desc  "Removing the \"yast2-tftp-server\" package decreases the risk of the
accidental (or intentional) activation of tftp services."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000095-GPOS-00049"
  tag "gid": "V-89613"
  tag "rid": "SV-100263r1_rule"
  tag "stig_id": "VRAU-SL-000475"
  tag "fix_id": "F-96355r1_fix"
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
  tag "check": "Check if \"yast2-tftp-server\" is installed:

# rpm -q yast2-tftp-server

If a \"yast2-tftp-server\" package is listed, this is a finding."
  tag "fix": "To remove the \"yast2-tftp-server\" package, use the following
command:

rpm -e yast2-tftp-server"

describe package('yast2-tftp-server') do
  it { should_not be_installed }
end

end

