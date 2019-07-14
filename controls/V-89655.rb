control "V-89655" do
  title "Sendmail logging must not be set to less than nine in the sendmail.cf
file."
  desc  "If Sendmail is not configured to log at level 9, system logs may not
contain the information necessary for tracking unauthorized use of the sendmail
service."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89655"
  tag "rid": "SV-100305r1_rule"
  tag "stig_id": "VRAU-SL-000590"
  tag "fix_id": "F-96397r1_fix"
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
  tag "check": "Check sendmail to determine if the logging level is set to
level nine:

# grep \"O L\" /etc/sendmail.cf
OR
# grep LogLevel /etc/sendmail.cf

If logging is set to less than nine, this is a finding."
  tag "fix": "Edit the sendmail.cf file, locate the \"O L\" or \"LogLevel\"
entry and change it to \"9\"."
end

