control "V-89757" do
  title "The SLES for vRealize must protect audit tools from unauthorized
modification."
  desc  "Protecting audit information also includes identifying and protecting
the tools used to view and manipulate log data. Therefore, protecting audit
tools is necessary to prevent unauthorized operation on audit information.

    Operating systems providing tools to interface with audit information will
leverage user permissions and roles identifying the user accessing the tools
and the corresponding rights the user has in order to make access decisions
regarding the modification of audit tools.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000257-GPOS-00098"
  tag "gid": "V-89757"
  tag "rid": "SV-100407r1_rule"
  tag "stig_id": "VRAU-SL-000910"
  tag "fix_id": "F-96499r1_fix"
  tag "cci": ["CCI-001494"]
  tag "nist": ["AU-9", "Rev_4"]
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
  tag "check": "The following command will list which audit files on the system
where the group-ownership has been modified:

# rpm -V audit | grep '^......G'

If there is output, this is a finding."
  tag "fix": "Run the following command to reset audit permissions to the
correct values:

sudo rpm --setperms audit-1.8-0.34.26"
end

