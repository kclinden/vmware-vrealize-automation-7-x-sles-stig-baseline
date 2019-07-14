control "V-89667" do
  title "The SMTP service must not use .forward files."
  desc  "The .forward file allows users to automatically forward mail to
another system. Use of .forward files could allow the unauthorized forwarding
of mail and could potentially create mail loops, which could degrade system
performance."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89667"
  tag "rid": "SV-100317r1_rule"
  tag "stig_id": "VRAU-SL-000620"
  tag "fix_id": "F-96409r1_fix"
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
  tag "check": "Check if forwarding from sendmail:

# grep \"0 ForwardPath\" /etc/sendmail.cf

If the entry contains a file path and is not commented out, this is a finding."
  tag "fix": "Disable forwarding for sendmail and remove \".forward\" files
from the system:

Remove all .forward files on the system:

# find / -name .forward -delete

Use the following command to disable forwarding:

# sed -i \"s/O ForwardPath/#O ForwardPath/\" /etc/sendmail.cf

Restart the sendmail service:

# service sendmail restart"
end

