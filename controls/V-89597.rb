control "V-89597" do
  title "The system boot loader configuration files must be owned by root."
  desc  "The system's boot loader configuration files are critical to the
integrity of the system and must be protected. Unauthorized modification of
these files resulting from improper ownership could compromise the system's
boot loader configuration."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000080-GPOS-00048"
  tag "gid": "V-89597"
  tag "rid": "SV-100247r1_rule"
  tag "stig_id": "VRAU-SL-000435"
  tag "fix_id": "F-96339r1_fix"
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

If the owner of the file is not \"root\", this is a finding."
  tag "fix": "Change the ownership of the file:

# chown root /boot/grub/menu.lst"
end

