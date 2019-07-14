control "V-89817" do
  title "The SLES for vRealize must implement non-executable data to protect
its memory from unauthorized code execution."
  desc  "Some adversaries launch attacks with the intent of executing code in
non-executable regions of memory or in memory locations that are prohibited.
Security safeguards employed to protect memory include, for example, data
execution prevention and address space layout randomization. Data execution
prevention safeguards can either be hardware-enforced or software-enforced with
hardware providing the greater strength of mechanism.

    Examples of attacks are buffer overflow attacks.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000433-GPOS-00192"
  tag "gid": "V-89817"
  tag "rid": "SV-100467r1_rule"
  tag "stig_id": "VRAU-SL-001335"
  tag "fix_id": "F-96559r1_fix"
  tag "cci": ["CCI-002824"]
  tag "nist": ["SI-16", "Rev_4"]
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
  tag "check": "The stock kernel has support for non-executable program stacks
compiled in by default. Verify that the option was specified when the kernel
was built:

# grep -i \"execute\" /var/log/boot.msg

The message: \"NX (Execute Disable) protection: active\" will be written in the
boot log when compiled in the kernel. This is the default for x86_64.

To activate this support, the “noexec=on” kernel parameter must be specified at
boot time. Check for a message with the following command:

# grep –i \"noexec\" /var/log/boot.msg

The message: \"Kernel command line: <boot parameters> noexec=on\" will be
written to the boot log when properly appended to the /boot/grub/menu.lst file.

If non-executable program stacks have not been configured, this is a finding."
  tag "fix": "Edit the /boot/grub/menu.lst file and add “noexec=on” to the end
of each kernel line entry. A system restart is required to implement this
change."
end

