control "V-89603" do
  title "The system must have USB Mass Storage disabled unless needed."
  desc  "USB is a common computer peripheral interface. USB devices may include
storage devices that could be used to install malicious software on a system or
exfiltrate data."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000095-GPOS-00049"
  tag "gid": "V-89603"
  tag "rid": "SV-100253r1_rule"
  tag "stig_id": "VRAU-SL-000450"
  tag "fix_id": "F-96345r1_fix"
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
  tag "check": "If the system needs USB storage, this vulnerability is not
applicable.

Check if \"usb-storage\" is prevented from loading:

# grep \"install usb-storage /bin/true\" /etc/modprobe.conf
/etc/modprobe.conf.local /etc/modprobe.d/*

If no results are returned, this is a finding."
  tag "fix": "Prevent the \"usb-storage\" module from loading:

# echo \"install usb-storage /bin/true\" >> /etc/modprobe.conf.local"
end

