control "V-89641" do
  title "Mail relaying must be restricted."
  desc  "If unrestricted mail relaying is permitted, unauthorized senders could
use this host as a mail relay for the purpose of sending spam or other
unauthorized activity."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89641"
  tag "rid": "SV-100291r1_rule"
  tag "stig_id": "VRAU-SL-000555"
  tag "fix_id": "F-96383r1_fix"
  tag "cci": ["CCI-000382"]
  tag "nist": ["CM-7 b", "Rev_4"]
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
  tag "check": "Determine if Sendmail only binds to loopback addresses by
examining the \"DaemonPortOptions\" configuration options.

# grep -i \"O DaemonPortOptions\" /etc/sendmail.cf

If there are uncommented DaemonPortOptions lines, and all such lines specify
system loopback addresses, this is not a finding.

Otherwise, determine if Sendmail is configured to allow open relay operation.

# grep -i promiscuous_relay /etc/mail/sendmail.mc

If the promiscuous relay feature is enabled, this is a finding."
  tag "fix": "If the SLES for vRealize does not need to receive mail from
external hosts, add one or more \"DaemonPortOptions\" lines referencing system
loopback addresses (such as \"O
DaemonPortOptions=Addr=127.0.0.1,Port=smtp,Name=MTA\") and remove lines
containing non-loopback addresses.

# sed -i \"s/O DaemonPortOptions=Name=MTA/O
DaemonPortOptions=Addr=127.0.0.1,Port=smtp,Name=MTA/\" /etc/sendmail.cf

Restart the sendmail service:

# service sendmail restart"

#currently only checking if this is installed; This service should not exist on the system ootb. 
describe service('sendmail') do
  it { should_not be_installed }
  it { should_not be_enabled }
end

end

