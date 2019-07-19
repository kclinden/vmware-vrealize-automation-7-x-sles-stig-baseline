control "V-89605" do
  title "The system must have USB disabled unless needed."
  desc  "USB is a common computer peripheral interface. USB devices may include
storage devices that could be used to install malicious software on a system or
exfiltrate data."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000095-GPOS-00049"
  tag "gid": "V-89605"
  tag "rid": "SV-100255r1_rule"
  tag "stig_id": "VRAU-SL-000455"
  tag "fix_id": "F-96347r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
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
  tag "check": "If the system needs USB, this vulnerability is not applicable.

Check if the directory /proc/bus/usb exists.

If the directory /proc/bus/usb exists, this is a finding."
  tag "fix": "Edit the grub bootloader file /boot/grub/menu.lst by appending
the \"nousb\" parameter to the kernel boot line."

describe directory('/proc/bus/usb') do
  it{should_not exist}
end

end

