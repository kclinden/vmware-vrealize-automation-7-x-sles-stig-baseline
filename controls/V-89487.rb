control "V-89487" do
  title "The SLES for vRealize must produce audit records."
  desc  "Without establishing what type of events occurred, it would be
difficult to establish, correlate, and investigate the events leading up to an
outage or attack.

    Audit record content that may be necessary to satisfy this requirement
includes, for example, time stamps, source and destination addresses,
user/process identifiers, event descriptions, success/fail indications,
filenames involved, and access control or flow control rules invoked.

    Associating event types with detected events in the operating system audit
logs provides a means of investigating an attack; recognizing resource
utilization or capacity thresholds; or identifying an improperly configured
operating system.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000037-GPOS-00015"
  tag "gid": "V-89487"
  tag "rid": "SV-100137r1_rule"
  tag "stig_id": "VRAU-SL-000085"
  tag "fix_id": "F-96229r1_fix"
  tag "cci": ["CCI-000130"]
  tag "nist": ["AU-3", "Rev_4"]
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

If the service is not running, this is a finding."
  tag "fix": "Enable the \"auditd\" service by performing the following
commands:

# chkconfig auditd on
# service auditd start"

describe service('auditd') do
  it { should be_installed }
  it { should be_enabled }
  it { should be_running }
end

end

