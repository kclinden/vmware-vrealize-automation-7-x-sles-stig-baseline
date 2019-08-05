control "V-89821" do
  title "The SLES for vRealize must verify correct operation of all security
functions."
  desc  "Without verification of the security functions, security functions may
not operate correctly and the failure may go unnoticed. Security function is
defined as the hardware, software, and/or firmware of the information system
responsible for enforcing the system security policy and supporting the
isolation of code and data on which the protection is based. Security
functionality includes, but is not limited to, establishing system accounts,
configuring access authorizations (i.e., permissions, privileges), setting
events to be audited, and setting intrusion detection parameters.

    This requirement applies to operating systems performing security function
verification/testing and/or systems and environments that require this
functionality.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000445-GPOS-00199"
  tag "gid": "V-89821"
  tag "rid": "SV-100471r1_rule"
  tag "stig_id": "VRAU-SL-001350"
  tag "fix_id": "F-96563r1_fix"
  tag "cci": ["CCI-002696"]
  tag "nist": ["SI-6 a", "Rev_4"]
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
  tag "check": "Verify the SLES for vRealize produces audit records by running
the following command to determine the current status of the \"auditd\" service:

# service auditd status

If the service is enabled, the returned message must contain the following text:

Checking for service auditd                running

If the service is not \"running\", this is a finding."
  tag "fix": "Enable the \"auditd\" service by performing the following
commands:

# chkconfig auditd on
# service auditd start"

describe service('auditd') do
  it {should be_running}
  it {should be_enabled}
end

end

