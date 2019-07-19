control "V-89609" do
  title "The rsh-server package must not be installed."
  desc  "The \"rsh-server\" package provides several obsolete and insecure
network services. Removing it decreases the risk of accidental (or intentional)
activation of those services."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000095-GPOS-00049"
  tag "gid": "V-89609"
  tag "rid": "SV-100259r1_rule"
  tag "stig_id": "VRAU-SL-000465"
  tag "fix_id": "F-96351r1_fix"
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
  tag "check": "Check if \"rsh-server\" is installed:

# rpm -q rsh-server

If an \"rsh-server\" package is listed, this is a finding."
  tag "fix": "To remove the \"telnet-server\" package, use the following
command:

rpm -e rsh-server"

describe package('rsh-server') do
  it { should_not be_installed }
end

end

