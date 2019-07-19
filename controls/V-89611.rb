control "V-89611" do
  title "The ypserv package must not be installed."
  desc  "Removing the \"ypserv\" package decreases the risk of the accidental
(or intentional) activation of NIS or NIS+ services."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000095-GPOS-00049"
  tag "gid": "V-89611"
  tag "rid": "SV-100261r1_rule"
  tag "stig_id": "VRAU-SL-000470"
  tag "fix_id": "F-96353r1_fix"
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
  tag "check": "Check if \"ypserv\" is installed:

# rpm -q ypserv

If there is a \"ypserv\" package listed, this is a finding."
  tag "fix": "To remove the \"telnet-server\" package use the following command:

rpm -e ypserv"

describe package('ypserv') do
  it { should_not be_installed }
end

end

