control "V-89549" do
  title "The SLES for vRealize must generate audit records when
successful/unsuccessful attempts to access privileges occur. The SLES for
vRealize must generate audit records for all discretionary access control
permission modifications using fsetxattr."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000064-GPOS-00033"
  tag "gid": "V-89549"
  tag "rid": "SV-100199r1_rule"
  tag "stig_id": "VRAU-SL-000290"
  tag "fix_id": "F-96291r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
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
  tag "check": "To determine if the system is configured to audit calls to the
\"fsetxattr\" system call, run the following command:

# auditctl -l | grep syscall | grep fsetxattr

If the system is configured to audit this activity, it will return several
lines, such as:

LIST_RULES: exit,always arch=3221225534 (0xc000003e)
syscall=lchown,sethostname,init_module,delete_module,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,clock_settime

If no lines are returned, this is a finding."
  tag "fix": "At a minimum, the SLES for vRealize audit system should collect
file permission changes for all users and \"root\". Add the following to
\"/etc/audit/audit.rules\":

-a always,exit -F arch=b64 -S fsetxattr

Or run the following command to implement all logging requirements:

# /etc/dodscript.sh"

describe file("/etc/audit/audit.rules") do
  its("content") { should match %r{-S fsetxattr} } #this may be too exclusive, and might need to be expanded.
end

end

