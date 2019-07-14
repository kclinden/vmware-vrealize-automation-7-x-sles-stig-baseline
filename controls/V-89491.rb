control "V-89491" do
  title "The SLES for vRealize must shut down by default upon audit failure
(unless availability is an overriding concern)."
  desc  "It is critical that when the operating system is at risk of failing to
process audit logs as required, it takes action to mitigate the failure. Audit
processing failures include: software/hardware errors; failures in the audit
capturing mechanisms; and audit storage capacity being reached or exceeded.
Responses to audit failure depend upon the nature of the failure mode.

    When availability is an overriding concern, other approved actions in
response to an audit failure are as follows:

    1) If the failure was caused by the lack of audit record storage capacity,
the operating system must continue generating audit records if possible
(automatically restarting the audit service if necessary), overwriting the
oldest audit records in a first-in-first-out manner.

    2) If audit records are sent to a centralized collection server and
communication with this server is lost or the server fails, the operating
system must queue audit records locally until communication is restored or
until the audit records are retrieved manually. Upon restoration of the
connection to the centralized collection server, action should be taken to
synchronize the local audit data with the collection server.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000047-GPOS-00023"
  tag "gid": "V-89491"
  tag "rid": "SV-100141r1_rule"
  tag "stig_id": "VRAU-SL-000130"
  tag "fix_id": "F-96233r1_fix"
  tag "cci": ["CCI-000140"]
  tag "nist": ["AU-5 b", "Rev_4"]
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
  tag "check": "Verify the /etc/audit/auditd.conf has the \"disk_full_action\",
\"disk_error_action\", and \"admin_disk_space_left\" parameters set.

# grep disk_full_action /etc/audit/auditd.conf

If the \"disk_full_action\" parameter is missing or set to \"suspend\" or
\"ignore\" this is a finding.

# grep disk_error_action /etc/audit/auditd.conf

If the \"disk_error_action\" parameter is missing or set to \"suspend\" or
\"ignore\" this is a finding.

# grep admin_space_left_action /etc/audit/auditd.conf

If the \"admin_space_left_action\" parameter is missing or set to \"suspend\"
or \"ignore\" this is a finding."
  tag "fix": "Edit /etc/audit/auditd.conf and set the \"disk_full_action\",
\"disk_error_action\", and \"admin_space_left_action\" parameters to \"syslog\"
with the following commands:

# sed -i \"/^[^#]*disk_full_action/ c\\disk_full_action = SYSLOG\"
/etc/audit/auditd.conf
# sed -i \"/^[^#]*disk_error_action/ c\\disk_error_action = SYSLOG\"
/etc/audit/auditd.conf
# sed -i \"/^[^#]*admin_space_left_action/ c\\admin_space_left_action =
SYSLOG\" /etc/audit/auditd.conf

For certain systems, the need for availability outweighs the need to log all
actions, and a different setting should be determined."
end

