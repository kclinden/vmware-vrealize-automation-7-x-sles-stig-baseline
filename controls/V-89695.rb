control "V-89695" do
  title "The SLES for vRealize must enforce SSHv2 for network access to
privileged accounts."
  desc  "A replay attack may enable an unauthorized user to gain access to the
operating system. Authentication sessions between the authenticator and the
operating system validating the user credentials must not be vulnerable to a
replay attack.

    An authentication process resists replay attacks if it is impractical to
achieve a successful authentication by recording and replaying a previous
authentication message.

    A privileged account is any information system account with authorizations
of a privileged user.

    Techniques used to address this include protocols using nonces (e.g.,
numbers generated for a specific one-time use) or challenges (e.g., TLS,
WS_Security). Additional techniques include time-synchronous or
challenge-response one-time authenticators.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000112-GPOS-00057"
  tag "gid": "V-89695"
  tag "rid": "SV-100345r1_rule"
  tag "stig_id": "VRAU-SL-000710"
  tag "fix_id": "F-96437r1_fix"
  tag "cci": ["CCI-001941"]
  tag "nist": ["IA-2 (8)", "Rev_4"]
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
  tag "check": "Verify that the SLES for vRealize enforces SSHv2 for network
access to privileged accounts by running the following command:

Replace [ADDRESS] in the following command with the correct IP address based on
the current system configuration.
# ssh -1 [ADDRESS]

An example of the command usage is as follows:
# ssh -1 localhost

The output must be the following:

Protocol major versions differ: 1 vs. 2

If the output is not as listed above, this is a finding.

OR

Verify that the ssh is configured to enforce SSHv2 for network access to
privileged accounts by running the following command:

# grep Protocol /etc/ssh/sshd_config

If the result is not \"Protocol 2\", this is a finding."
  tag "fix": "Configure the SLES for vRealize to enforce SSHv2 for network
access to privileged accounts by running the following commands:

# sed -i 's/^.*\\bProtocol\\b.*$/Protocol 2/' /etc/ssh/sshd_config

Restart the ssh service:

# service sshd restart"

# http://inspec.io/docs/reference/resources/sshd_config/
describe sshd_config do
  its('Protocol') { should eq '2' }
end

end

