control "V-89711" do
  title "The SLES for vRealize must employ strong authenticators in the
establishment of nonlocal maintenance and diagnostic sessions."
  desc  "If maintenance tools are used by unauthorized personnel, they may
accidentally or intentionally damage or compromise the system. The act of
managing systems and applications includes the ability to access sensitive
application information, such as system configuration details, diagnostic
information, user information, and potentially sensitive application data.

    Some maintenance and test tools are either standalone devices with their
own operating systems or are applications bundled with an operating system.

    Nonlocal maintenance and diagnostic activities are those activities
conducted by individuals communicating through a network, either an external
network (e.g., the Internet) or an internal network. Local maintenance and
diagnostic activities are those activities carried out by individuals
physically present at the information system or information system component
and not communicating across a network connection. Typically, strong
authentication requires authenticators that are resistant to replay attacks and
employ multifactor authentication. Strong authenticators include, for example,
PKI where certificates are stored on a token protected by a password,
passphrase, or biometric.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000125-GPOS-00065"
  tag "gid": "V-89711"
  tag "rid": "SV-100361r1_rule"
  tag "stig_id": "VRAU-SL-000760"
  tag "fix_id": "F-96453r2_fix"
  tag "cci": ["CCI-000877"]
  tag "nist": ["MA-4 c", "Rev_4"]
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
  its('Ciphers') { should cmp 'aes256-ctr,aes128-ctr' }
end

end

