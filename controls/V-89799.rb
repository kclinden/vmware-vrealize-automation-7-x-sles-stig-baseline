control "V-89799" do
  title "The SLES for vRealize must audit the enforcement actions used to
restrict access associated with changes to the system."
  desc  "Without auditing the enforcement of access restrictions against
changes to the application configuration, it will be difficult to identify
attempted attacks and an audit trail will not be available for forensic
investigation for after-the-fact actions.

    Enforcement actions are the methods or mechanisms used to prevent
unauthorized changes to configuration settings. Enforcement action methods may
be as simple as denying access to a file based on the application of file
permissions (access restriction). Audit items may consist of lists of actions
blocked by access restrictions or changes identified after the fact.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000365-GPOS-00152"
  tag "gid": "V-89799"
  tag "rid": "SV-100449r1_rule"
  tag "stig_id": "VRAU-SL-001165"
  tag "fix_id": "F-96541r1_fix"
  tag "cci": ["CCI-001814"]
  tag "nist": ["CM-5 (1)", "Rev_4"]
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
  it {should be_enabled}
  it {should be_running}
end

end

