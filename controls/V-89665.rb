control "V-89665" do
  title "The SMTP service SMTP greeting must not provide version information."
  desc  "The version of the SMTP service can be used by attackers to plan an
attack based on vulnerabilities present in the specific version."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89665"
  tag "rid": "SV-100315r1_rule"
  tag "stig_id": "VRAU-SL-000615"
  tag "fix_id": "F-96407r1_fix"
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
  tag "check": "To check for the sendmail version being displayed in the
greeting:

# more /etc/sendmail.cf | grep SmtpGreetingMessage

If it returns the following:

O SmtpGreetingMessage=$j Sendmail $v/$Z; $b

Then sendmail is providing version information, and this is a finding."
  tag "fix": "Change the \"O SmtpGreetingMessage\" line in the /etc/sendmail.cf
file to:

O SmtpGreetingMessage= Mail Server Ready ; $b"
end

