control "V-89661" do
  title "The SMTP service log file must have mode 0644 or less permissive."
  desc  "If the SMTP service log file is more permissive than 0644,
unauthorized users may be allowed to change the log file."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89661"
  tag "rid": "SV-100311r1_rule"
  tag "stig_id": "VRAU-SL-000605"
  tag "fix_id": "F-96403r1_fix"
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

If the log file permissions are greater than \"0644\", this is a finding."
  tag "fix": "Change the mode of the sendmail log files:

# chmod 0644 <sendmail log file>"
end

