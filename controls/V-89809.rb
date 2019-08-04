control "V-89809" do
  title "The SLES for vRealize must implement NSA-approved cryptography to
protect classified information in accordance with applicable federal laws,
Executive Orders, directives, policies, regulations, and standards."
  desc  "Use of weak or untested encryption algorithms undermines the purposes
of utilizing encryption to protect data. The operating system must implement
cryptographic modules adhering to the higher standards approved by the federal
government since this provides assurance they have been tested and validated."
  impact 0.7
  tag "severity": nil
  tag "gtitle": "SRG-OS-000396-GPOS-00176"
  tag "gid": "V-89809"
  tag "rid": "SV-100459r1_rule"
  tag "stig_id": "VRAU-SL-001265"
  tag "fix_id": "F-96551r2_fix"
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
  tag "check": "Check the SSH daemon configuration for DoD-approved encryption
to protect the confidentiality of SSH remote connections by performing the
following commands:

Check the \"Ciphers\" setting in the \"sshd_config\" file.

# grep -i Ciphers /etc/ssh/sshd_config  | grep -v '#'

The output must contain either nothing or any number of the following
algorithms:

aes128-ctr, aes256-ctr.

If the output contains an algorithm not listed above, this is a finding.

Expected Output:
Ciphers aes256-ctr,aes128-ctr"
  tag "fix": "Update the \"Ciphers\" directive with the following command:

# sed -i \"/^[^#]*Ciphers/ c\\Ciphers aes256-ctr,aes128-ctr\"
/etc/ssh/sshd_config

Save and close the file.

Restart the sshd process:

# service sshd restart"

describe sshd_config do
  its('Ciphers') {should cmp 'aes256-ctr,aes128-ctr'}
end

end

