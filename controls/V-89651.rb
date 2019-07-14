control "V-89651" do
  title "Files executed through a mail aliases file must be group-owned by
root, bin, sys, or system, and must reside within a directory group-owned by
root, bin, sys, or system."
  desc  "If a file executed through a mail aliases file is not group-owned by
root or a system group, it may be subject to unauthorized modification.
Unauthorized modification of files executed through aliases may allow
unauthorized users to attain root privileges."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89651"
  tag "rid": "SV-100301r1_rule"
  tag "stig_id": "VRAU-SL-000580"
  tag "fix_id": "F-96393r1_fix"
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
  tag "check": "Examine the contents of the /etc/aliases file:

# more /etc/aliases

Examine the aliases file for any directories or paths that may be utilized:

# ls -lL <file referenced from aliases>

Check the permissions for any paths referenced.

If the group-owner of any file is not \"root\", \"bin\", \"sys\", or
\"system\", this is a finding."
  tag "fix": "Change the group-ownership of the file referenced from
/etc/mail/aliases:

# chgrp root <file referenced from aliases>"
end

