control "V-89801" do
  title "The RPM package management tool must cryptographically verify the
authenticity of all software packages during installation."
  desc  "Changes to any software components can have significant effects on the
overall security of the operating system. This requirement ensures the software
has not been tampered with and that it has been provided by a trusted vendor.

    Accordingly, patches, service packs, device drivers, or operating system
components must be signed with a certificate recognized and approved by the
organization.

    Verifying the authenticity of the software prior to installation validates
the integrity of the patch or upgrade received from a vendor. This ensures the
software has not been tampered with and that it has been provided by a trusted
vendor. Self-signed certificates are disallowed by this requirement. The
operating system should not have to verify the software again. This requirement
does not mandate DoD certificates for this purpose; however, the certificate
used to verify the software must be from an approved CA.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000366-GPOS-00153"
  tag "gid": "V-89801"
  tag "rid": "SV-100451r1_rule"
  tag "stig_id": "VRAU-SL-001170"
  tag "fix_id": "F-96543r1_fix"
  tag "cci": ["CCI-001749"]
  tag "nist": ["CM-5 (3)", "Rev_4"]
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
  tag "check": "Verify RPM signature validation is not disabled:

# grep nosignature /usr/lib/rpm/rpmrc ~root/.rpmrc

The result should either respond with no such file or directory, or an empty
return.

If any configuration is found, this is a finding."
  tag "fix": "Edit the RPM configuration files containing the \"nosignature\"
option and remove the option."
end

