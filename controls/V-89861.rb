control "V-89861" do
  title "The SLES for vRealize must implement NIST FIPS-validated cryptography
for the following: to provision digital signatures, to generate cryptographic
hashes, and to protect unclassified information requiring confidentiality and
cryptographic protection in accordance with applicable federal laws, Executive
Orders, directives, policies, regulations, and standards."
  desc  "Use of weak or untested encryption algorithms undermines the purposes
of utilizing encryption to protect data. The SLES for vRealize must implement
cryptographic modules adhering to the higher standards approved by the federal
government since this provides assurance they have been tested and validated."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000478-GPOS-00223"
  tag "gid": "V-89861"
  tag "rid": "SV-100511r1_rule"
  tag "stig_id": "VRAU-SL-001490"
  tag "fix_id": "F-96603r1_fix"
  tag "cci": ["CCI-002450"]
  tag "nist": ["SC-13", "Rev_4"]
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
  tag "check": "Check the SSH daemon configuration for allowed MACs:

# grep -i macs /etc/ssh/sshd_config | grep -v '^#'

If no lines are returned, or the returned MACs list contains any MAC other than
\"hmac-sha1\", this is a finding."
  tag "fix": "Edit the SSH daemon configuration and remove any MACs other than
\"hmac-sha1\". If necessary, add a \"MACs\" line."

describe sshd_config do
  its('macs') {should cmp 'hmac-sha1'}
end

end

