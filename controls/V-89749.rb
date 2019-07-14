control "V-89749" do
  title "The SLES for vRealize must implement cryptography to protect the
integrity of remote access sessions."
  desc  "Without cryptographic integrity protections, information can be
altered by unauthorized users without detection.

    Remote access (e.g., RDP) is access to DoD nonpublic information systems by
an authorized user (or an information system) communicating through an
external, non-organization-controlled network. Remote access methods include,
for example, dial-up, broadband, and wireless.

    Cryptographic mechanisms used for protecting the integrity of information
include, for example, signed hash functions using asymmetric cryptography
enabling distribution of the public key to verify the hash information while
maintaining the confidentiality of the secret key used to generate the hash.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000250-GPOS-00093"
  tag "gid": "V-89749"
  tag "rid": "SV-100399r1_rule"
  tag "stig_id": "VRAU-SL-000890"
  tag "fix_id": "F-96491r2_fix"
  tag "cci": ["CCI-001453"]
  tag "nist": ["AC-17 (2)", "Rev_4"]
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
end

