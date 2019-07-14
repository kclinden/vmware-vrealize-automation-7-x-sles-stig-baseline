control "V-89657" do
  title "The system syslog service must log informational and more severe SMTP
service messages."
  desc  "If informational and more severe SMTP service messages are not logged,
malicious activity on the system may go unnoticed."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89657"
  tag "rid": "SV-100307r1_rule"
  tag "stig_id": "VRAU-SL-000595"
  tag "fix_id": "F-96399r1_fix"
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
  tag "check": "Check the /etc/syslog-ng/syslog-ng.conf for the following log
entries:

filter f_mailinfo { level(info) and facility(mail); };
filter f_mailwarn { level(warn) and facility(mail); };
filter f_mailerr { level(err, crit) and facility(mail); };
filter f_mail { facility(mail); };

If present, this is not a finding."
  tag "fix": "Edit the /etc/syslog-ng/syslog-ng.conf file and add the following
log entries:

filter f_mailinfo { level(info) and facility(mail); };
filter f_mailwarn { level(warn) and facility(mail); };
filter f_mailerr { level(err, crit) and facility(mail); };
filter f_mail { facility(mail); };

destination mailinfo { file(\"/var/log/mail.info\"); };
log { source(src); filter(f_mailinfo); destination(mailinfo); };

destination mailwarn { file(\"/var/log/mail.warn\"); };
log { source(src); filter(f_mailwarn); destination(mailwarn); };

destination mailerr { file(\"/var/log/mail.err\" fsync(yes)); };
log { source(src); filter(f_mailerr); destination(mailerr); };"
end

