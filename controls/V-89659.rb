control "V-89659" do
  title "The SMTP service log files must be owned by root."
  desc  "If the SMTP service log file is not owned by root, then unauthorized
personnel may modify or delete the file to hide a system compromise."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89659"
  tag "rid": "SV-100309r1_rule"
  tag "stig_id": "VRAU-SL-000600"
  tag "fix_id": "F-96401r1_fix"
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
  tag "check": "Check the permissions on the mail log files:

# ls -la /var/log/mail
# ls -la /var/log/mail.info
# ls -la /var/log/mail.warn
# ls -la /var/log/mail.err

If any mail log file is not owned by \"root\", this is a finding."
  tag "fix": "Change the ownership of the sendmail log files:

# chown root <sendmail log file>"
end

