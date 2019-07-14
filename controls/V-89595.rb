control "V-89595" do
  title "The system boot loader configuration file(s) must have mode 0600 or
less permissive."
  desc  "File permissions more permissive than 0600 on boot loader
configuration files could allow an unauthorized user to view or modify
sensitive information pertaining to system boot instructions."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000080-GPOS-00048"
  tag "gid": "V-89595"
  tag "rid": "SV-100245r1_rule"
  tag "stig_id": "VRAU-SL-000430"
  tag "fix_id": "F-96337r1_fix"
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
  tag "check": "Check the /boot/grub/menu.lst file:

# stat /boot/grub/menu.lst

If /boot/grub/menu.lst has a mode more permissive than \"0600\", this is a
finding."
  tag "fix": "Change the mode of the menu.lst file to \"0600\":

# chmod 0600 /boot/grub/menu.lst"
end

