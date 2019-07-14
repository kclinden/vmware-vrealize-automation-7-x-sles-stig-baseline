control "V-89599" do
  title "The system boot loader configuration file(s) must be group-owned by
root, bin, sys, or system."
  desc  "The system's boot loader configuration files are critical to the
integrity of the system and must be protected. Unauthorized modifications
resulting from improper group-ownership may compromise the boot loader
configuration."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000080-GPOS-00048"
  tag "gid": "V-89599"
  tag "rid": "SV-100249r1_rule"
  tag "stig_id": "VRAU-SL-000440"
  tag "fix_id": "F-96341r1_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
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
  tag "check": "Check /boot/grub/menu.lst ownership:

# stat /boot/grub/menu.lst

If the group-owner of the file is not \"root\", \"bin\", \"sys\", or
\"system\", this is a finding."
  tag "fix": "Change the group-ownership of the file:

# chgrp root /boot/grub/menu.lst"
end

