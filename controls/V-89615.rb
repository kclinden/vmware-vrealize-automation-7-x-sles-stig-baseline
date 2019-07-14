control "V-89615" do
  title "The tftp package must not be installed."
  desc  "The Trivial File Transfer Protocol (TFTP) is normally used only for
booting diskless workstations and for getting or saving network component
configuration files. Disabling the \"tftp\" protocol service ensures the system
is not acting over tftp, which does not provide encryption or authentication."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000095-GPOS-00049"
  tag "gid": "V-89615"
  tag "rid": "SV-100265r1_rule"
  tag "stig_id": "VRAU-SL-000490"
  tag "fix_id": "F-96357r1_fix"
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
  tag "check": "Check if \"tftp\" is installed:

# rpm -q tftp

If there is a \"tftp\" package listed, this is a finding."
  tag "fix": "To remove the \"tftp\" package use the following command:

rpm -e tftp"
end

