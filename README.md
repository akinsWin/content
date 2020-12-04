### /Advanced Threat Detection/Windows Process Monitoring
|                                                                                             workbooks                                                                                              |
|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|[DNS RCE CVE-2020-1350](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_exploit_cve_2020_1350.yml)                                                  |
|[Explorer Root Flag Process Tree Break](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_explorer_break_proctree.yml)                           |
|[Impacket Lateralization Detection](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_impacket_lateralization.yml)                                    |
|[Bypass UAC via Fodhelper.exe](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_uac_fodhelper.yml)                                                   |
|[Process Dump via Comsvcs DLL](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_comsvcs_procdump.yml)                                           |
|[Harvesting of Wifi Credentials Using netsh.exe](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_netsh_wifi_credential_harvesting.yml)              |
|[Copying Sensitive Files with Credential Data](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_copying_sensitive_files_with_credential_data.yml)    |
|[Fireball Archer Install](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_crime_fireball.yml)                                                       |
|[Judgement Panda Exfil Activity](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_apt_judgement_panda_gtr19.yml)                                     |
|[Suspicious Rundll32 Activity](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_execution_path.yml)                                             |
|[Audio Capture via PowerShell](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_powershell_audio_capture.yml)                                        |
|[Suspicious Program Location Process Starts](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_prog_location_process_starts.yml)                 |
|[Modification of Boot Configuration](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_bootconf_mod.yml)                                              |
|[Lazarus Session Highjacker](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_apt_lazarus_session_highjack.yml)                                      |
|[Svchost DLL Search Order Hijack](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_svchost_dll_search_order_hijack.yml)                           |
|[RedMimicry Winnti Playbook Execute](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_redmimicry_winnti_proc.yml)                                    |
|[ZOHO Dctask64 Process Injection](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_dctask64_proc_inject.yml)                                    |
|[Microsoft Office Product Spawning Windows Shell](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_office_shell.yml)                                 |
|[Suspicious Eventlog Clear or Configuration Using Wevtutil](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_eventlog_clear.yml)                |
|[Suspicious Csc.exe Source File Folder](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_csc_folder.yml)                                        |
|[Suspicious XOR Encoded PowerShell Command Line](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/powershell_xor_commandline.yml)                        |
|[PowerShell Encoded Character Syntax](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_powershell_encoded_param.yml)                            |
|[Certutil Encode](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_certutil_encode.yml)                                                         |
|[Net.exe Execution](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_net_execution.yml)                                                         |
|[Advanced IP Scanner](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_advanced_ip_scanner.yml)                                                      |
|[Suspicious Debugger Registration Cmdline](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_install_reg_debugger_backdoor.yml)                       |
|[Suspicious AdFind Execution](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_adfind.yml)                                                      |
|[Stop Windows Service](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_service_stop.yml)                                                            |
|[WMI Backdoor Exchange Transport Agent](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_wmi_backdoor_exchange_transport_agent.yml)                  |
|[ZxShell Malware](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_apt_zxshell.yml)                                                                  |
|[Reconnaissance Activity with Net Command](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_commands_recon_activity.yml)                        |
|[Suspicious Commandline Escape](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_cli_escape.yml)                                                |
|[Remote PowerShell Session](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_remote_powershell_session_process.yml)                                  |
|[XSL Script Processing](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_xsl_script_processing.yml)                                                  |
|[Netsh Program Allowed with Suspcious Location](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_netsh_fw_add_susp_image.yml)                        |
|[Command Line Execution with Suspicious URL and AppData Strings](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_cmd_http_appdata.yml)         |
|[Detection of Possible Rotten Potato](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_possible_privilege_escalation_using_rotten_potato.yml)        |
|[Trickbot Malware Recon Activity](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_malware_trickbot_recon_activity.yml)                              |
|[Koadic Execution](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_hack_koadic.yml)                                                                 |
|[Shadow Copies Deletion Using Operating Systems Utilities](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_shadow_copies_deletion.yml)              |
|[PowerShell DownloadFile](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_ps_downloadfile.yml)                                                 |
|[Squirrel Lolbin](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_squirrel_lolbin.yml)                                                         |
|[Ping Hex IP](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_ping_hex_ip.yml)                                                                 |
|[Suspicious Use of CSharp Interactive Console](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_use_of_csharp_console.yml)                      |
|[Suspicious Outbound RDP Connections](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_susp_rdp.yml)                                              |
|[Windows Network Enumeration](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_net_enum.yml)                                                         |
|[Possible Applocker Bypass](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_possible_applocker_bypass.yml)                                          |
|[Rundll32 Internet Connection](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_rundll32_net_connections.yml)                                     |
|[Suspicious Double Extension](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_double_extension.yml)                                            |
|[Possible Process Hollowing Image Loading](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_susp_image_load.yml)                                  |
|[Possible App Whitelisting Bypass via WinDbg/CDB as a Shellcode Runner](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_cdb.yml)               |
|[Executables Started in Suspicious Folder](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_exec_folder.yml)                                    |
|[WMI Modules Loaded](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_wmi_module_load.yml)                                                        |
|[DNS Tunnel Technique from MuddyWater](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_apt_muddywater_dnstunnel.yml)                             |
|[Renamed PowerShell](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_renamed_powershell.yml)                                                        |
|[Interactive AT Job](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_interactive_at.yml)                                                            |
|[Domain Trust Discovery](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_trust_discovery.yml)                                                       |
|[Devtoolslauncher.exe Executes Specified Binary](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_devtoolslauncher.yml)                         |
|[Renamed SysInternals Debug View](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_renamed_debugview.yml)                                       |
|[Tap Installer Execution](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_tap_installer_execution.yml)                                              |
|[DTRACK Process Creation](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_malware_dtrack.yml)                                                       |
|[Suspicious Process Start Locations](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_run_locations.yml)                                        |
|[Grabbing Sensitive Hives via Reg Utility](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_grabbing_sensitive_hives_via_reg.yml)                    |
|[RDP Over Reverse SSH Tunnel](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_rdp_reverse_tunnel.yml)                                            |
|[Active Directory Parsing DLL Loaded Via Office Applications](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_susp_office_dsparse_dll_load.yml)  |
|[In-memory PowerShell](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_in_memory_powershell.yml)                                                 |
|[Suspicious Esentutl Use](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_esentutl_activity.yml)                                               |
|[Activity Related to NTDS.dit Domain Hash Retrieval](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/win_susp_vssadmin_ntds_activity.yml)               |
|[Load of dbghelp/dbgcore DLL from Suspicious Process](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_suspicious_dbghelp_dbgcore_load.yml)       |
|[CLR DLL Loaded Via Office Applications](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_susp_office_dotnet_clr_dll_load.yml)                    |
|[Active Directory Kerberos DLL Loaded Via Office Applications](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_susp_office_kerberos_dll_load.yml)|
|[PowerShell Execution](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_powershell_execution_moduleload.yml)                                      |
|[Unsigned Image Loaded Into LSASS Process](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_unsigned_image_loaded_into_lsass.yml)                 |
|[Mimikatz Detection LSASS Access](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_mimikatz_detection_lsass.yml)                                  |
|[WMI Persistence - Command Line Event Consumer](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_wmi_persistence_commandline_event_consumer.yml)  |
|[dotNET DLL Loaded Via Office Applications](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_susp_office_dotnet_assembly_dll_load.yml)            |
|[VBA DLL Loaded Via Microsoft Word](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_susp_winword_vbadll_load.yml)                                |
|[Fax Service DLL Search Order Hijack](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_susp_fax_dll.yml)                                          |
|[Windows Mangement Instrumentation DLL Loaded Via Microsoft Word](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/sysmon_susp_winword_wmidll_load.yml)  |
### /Advanced Threat Detection/Proxy Monitoring
|                                                                                    workbooks                                                                                    |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|[iOS Implant URL Pattern](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_ios_implant.yml)                                     |
|[Windows PowerShell User Agent](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_powershell_ua.yml)                             |
|[Bitsadmin to Uncommon TLD](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_ua_bitsadmin_susp_tld.yml)                         |
|[Flash Player Update from Suspicious Location](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_susp_flash_download_loc.yml)    |
|[PwnDrp Access](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_pwndrop.yml)                                                   |
|[Telegram API Access](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_telegram_api.yml)                                        |
|[Suspicious User Agent](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_ua_suspicious.yml)                                     |
|[Download from Suspicious Dyndns Hosts](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_download_susp_dyndns.yml)              |
|[Chafer Malware URL Pattern](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_chafer_malware.yml)                               |
|[Raw Paste Service Access](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_raw_paste_service_access.yml)                       |
|[APT User Agent](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_ua_apt.yml)                                                   |
|[Empire UserAgent URI Combo](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_empire_ua_uri_combos.yml)                         |
|[CobaltStrike Malleable (OCSP) Profile](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_cobalt_ocsp.yml)                       |
|[CobaltStrike Malleable OneDrive Browsing Traffic Profile](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_cobalt_onedrive.yml)|
|[Exploit Framework User Agent](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_ua_frameworks.yml)                              |
|[CobaltStrike Malleable Amazon Browsing Traffic Profile](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_cobalt_amazon.yml)    |
|[Turla ComRAT](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_turla_comrat.yml)                                               |
|[Download from Suspicious TLD](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_download_susp_tlds_blacklist.yml)               |
|[Malware User Agent](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_ua_malware.yml)                                           |
|[Crypto Miner User Agent](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_ua_cryptominer.yml)                                  |
|[APT40 Dropbox Tool User Agent](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_apt40.yml)                                     |
|[Empty User Agent](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_empty_ua.yml)                                               |
|[Hack Tool User Agent](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_ua_hacktool.yml)                                        |
|[Download EXE from Suspicious TLD](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_download_susp_tlds_whitelist.yml)           |
|[Windows WebDAV User Agent](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/proxy_downloadcradle_webdav.yml)                         |
### /Advanced Threat Detection/Webserver Exploits
|                                                                                                workbooks                                                                                                 |
|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|[Citrix ADS Exploitation CVE-2020-8193 CVE-2020-8195](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/web_citrix_cve_2020_8193_8195_exploit.yml)              |
|[Oracle WebLogic Exploit](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/web_cve_2018_2894_weblogic_exploit.yml)                                             |
|[Confluence Exploitation CVE-2019-3398](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/web_cve_2019_3398_confluence.yml)                                     |
|[Multiple Suspicious Resp Codes Caused by Single Client](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/web_multiple_suspicious_resp_codes_single_source.yml)|
|[Pulse Secure Attack CVE-2019-11510](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/web_pulsesecure_cve-2019-11510.yml)                                      |
|[CVE-2020-0688 Exchange Exploitation via Web Log](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/web_cve_2020_0688_msexchange.yml)                           |
|[Citrix Netscaler Attack CVE-2019-19781](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/web_citrix_cve_2019_19781_exploit.yml)                               |
|[CVE-2020-0688 Exploitation Attempt](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/web_exchange_cve_2020_0688_exploit.yml)                                  |
|[CVE-2020-5902 F5 BIG-IP Exploitation Attempt](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/web_cve_2020_5902_f5_bigip.yml)                                |
### /Advanced Threat Detection/DNS Monitoring
|                                                                               workbooks                                                                                |
|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|[Telegram Bot API Request](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/net_susp_telegram_api.yml)                       |
|[Cobalt Strike DNS Beaconing](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/net_mal_dns_cobaltstrike.yml)                 |
|[Suspicious DNS Query with B64 Encoded String](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/net_susp_dns_b64_queries.yml)|
|[Wannacry Killswitch Domain](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/net_wannacry_killswitch_domain.yml)            |
### /Basic Security Monitoring/Malware
|                                                                        workbooks                                                                        |
|---------------------------------------------------------------------------------------------------------------------------------------------------------|
|[Antivirus Relevant File Paths Alerts](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/av_relevant_files.yml)|
### /Cloud Security/Amazon Web Services
|                                                                              workbooks                                                                              |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|[AWS EC2 VM Export Failure](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/aws_ec2_vm_export_failure.yml)               |
|[AWS Config Disabling Channel/Recorder](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/aws_config_disable_recording.yml)|
|[AWS IAM Backdoor Users Keys](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/aws_iam_backdoor_users_keys.yml)           |
|[Restore Public AWS RDS Instance](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/aws_rds_public_db_restore.yml)         |
|[AWS EC2 Download Userdata](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/aws_ec2_download_userdata.yml)               |
|[AWS CloudTrail Important Change](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/aws_cloudtrail_disable_logging.yml)    |
|[AWS EC2 Startup Shell Script Change](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/aws_ec2_startup_script_change.yml) |
|[AWS RDS Master Password Change](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/aws_rds_change_master_password.yml)     |
|[AWS Root Credentials](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/aws_root_account_usage.yml)                       |
|[AWS GuardDuty Important Change](https://github.com/dnif-backyard/dnif-threat-detection/tree/initial-detection-wbs/sigma_wbs/aws_guardduty_disruption.yml)           |
